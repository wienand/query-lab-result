import base64
import datetime
import hashlib
import logging
import logging.handlers
import re
import secrets
import smtplib
import sys

import flask_sqlalchemy
import flask_wtf
import sqlalchemy as sa
import validate_email
import waitress
import wtforms
from flask import Flask, render_template, redirect, request, jsonify
from werkzeug.exceptions import Forbidden

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', filename='server.log')
streamHandler = logging.StreamHandler()
streamHandler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logging.getLogger().addHandler(streamHandler)

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PBKDF2_ROUNDS'] = 400000
app.config['PBKDF2_HASH_FUNCTION'] = 'sha256'
app.config['TOKEN_LIFETIME_IN_SECONDS'] = 35 * 60
app.config['CODE_REGEXP'] = '.*'
app.config['API_KEY'] = []
app.config.from_envvar('SSR_SETTINGS')
db = flask_sqlalchemy.SQLAlchemy(app)
max_total_query_requests = app.config.get('MAX_TOTAL_QUERIES', 10000)

if app.config.get('SMTP_ERROR_TO', False):
    mail_handler = logging.handlers.SMTPHandler(
        mailhost=app.config['SMTP_HOST'],
        fromaddr=app.config['SMTP_FROM'],
        toaddrs=app.config['SMTP_ERROR_TO'],
        subject='Application Error - ' + app.config['BASE_URL']
    )
    mail_handler.setLevel(logging.ERROR)
    mail_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))


class Observation(db.Model):
    __tablename__ = 'observation'
    hash = sa.Column(sa.types.LargeBinary, sa.ForeignKey('result.hash'), primary_key=True)
    identifier = sa.Column(sa.types.UnicodeText, primary_key=True)
    created_at = sa.Column(sa.types.DateTime, default=datetime.datetime.utcnow)
    result = sa.Column(sa.types.UnicodeText)
    comment = sa.Column(sa.types.UnicodeText)
    Result = db.relationship('Result', backref=db.backref('Observations', lazy=False))


class Result(db.Model):
    __tablename__ = 'result'
    hash = sa.Column(sa.types.LargeBinary, primary_key=True)
    created_at = sa.Column(sa.types.DateTime, default=datetime.datetime.utcnow)
    result = sa.Column(sa.types.UnicodeText)
    comment = sa.Column(sa.types.UnicodeText)

    # TODO: Visibility after a certain time since the last update
    # visible_from = sa.Column(sa.types.DateTime)

    def __repr__(self):
        return '%s: %s (%s)' % (self.hash, self.result, self.comment)

    @classmethod
    def get_or_create(cls, ident=None, result=None, comment=None, hash_value=None, **_):
        if hash_value is None:
            hash_value = b'0' + hashlib.pbkdf2_hmac(app.config['PBKDF2_HASH_FUNCTION'], ident.encode(), app.config['PEPPER'], app.config['PBKDF2_ROUNDS'])
        entry = cls.query.get(hash_value)
        if entry is None:
            entry = cls(hash=hash_value)
            db.session.add(entry)
        if type(result) == list:
            current_by_identifier = {x.identifier: x for x in entry.Observations}
            for observation in result:
                if observation['identifier'] in current_by_identifier:
                    sub_entry = current_by_identifier[observation['identifier']]
                else:
                    sub_entry = Observation(Result=entry, identifier=observation['identifier'])
                    db.session.add(sub_entry)
                cls.update_entry(sub_entry, **observation)
        else:
            cls.update_entry(entry, comment, result)
        return entry

    @classmethod
    def update_entry(cls, entry, comment, result, **_):
        if result:
            entry.result = result
        if comment:
            entry.comment = comment


class Token(db.Model):
    __tablename__ = 'token'
    token = sa.Column(sa.types.UnicodeText, primary_key=True)
    used = sa.Column(sa.types.Integer, default=0)
    created_at = sa.Column(sa.types.DateTime, default=datetime.datetime.utcnow)
    requested_by = sa.Column(sa.types.UnicodeText)

    def __repr__(self):
        return '%s (from: %s, on: %s)' % (self.token, self.requested_by, self.created_at)


class Access(db.Model):
    __tablename__ = 'access'
    id = sa.Column(sa.types.Integer, primary_key=True)
    hash = sa.Column(sa.types.LargeBinary, sa.ForeignKey('result.hash'))
    token = sa.Column(sa.types.UnicodeText, sa.ForeignKey('token.token'))
    timestamp = sa.Column(sa.types.DateTime, default=datetime.datetime.utcnow)
    Token = db.relationship('Token', backref=db.backref('Access', lazy=True))
    Result = db.relationship('Result', backref=db.backref('Access', lazy=True))


def normalize_phone_number(phone_number):
    if phone_number.startswith('00'):
        return '+' + phone_number[2:]
    if phone_number.startswith('0'):
        return '+49' + phone_number[1:]


def generate_token():
    characters_for_token = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    # noinspection PyUnusedLocal
    token = ''.join(secrets.choice(characters_for_token) for x in range(3 * 4))
    return 'LQ-' + token[0:4] + '-' + token[4:8] + '-' + token[8:12]


def send_token_email(recipient, token):
    message = app.config['SMTP_TOKEN_TEMPLATE'].format(sender=app.config['SMTP_FROM'], base_url=app.config['BASE_URL'], to=recipient, token=token)

    with smtplib.SMTP(app.config['SMTP_HOST']) as smtp:
        smtp.sendmail(app.config['SMTP_FROM'], [recipient] + app.config.get('SMTP_BCC', []), message)


def send_token_by_sms(phone_number, token):
    send_token_email(normalize_phone_number(phone_number) + app.config['SMS_GATEWAY_EMAIL'], token)


def send_token_by_email(email, token):
    send_token_email(email, token)


class RequestTokenForm(flask_wtf.FlaskForm):
    email_or_mobile = wtforms.StringField('email_or_mobile', validators=[wtforms.validators.InputRequired(), wtforms.validators.Length(6, 254)])


class RequestResultForm(flask_wtf.FlaskForm):
    code = wtforms.StringField('code', validators=[wtforms.validators.regexp(app.config['CODE_REGEXP'], flags=re.IGNORECASE)])
    token = wtforms.StringField('token', validators=[wtforms.validators.regexp('^ *LQ-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4} *$', flags=re.IGNORECASE)])


@app.route('/', methods=['GET', 'POST'])
def route_index():
    form = RequestTokenForm()
    user_input = form.email_or_mobile.data
    if form.validate_on_submit():
        user_input = user_input.strip()
        if validate_email.validate_email(user_input):
            token = Token(token=generate_token(), requested_by=user_input)
            db.session.add(token)
            db.session.commit()
            send_token_by_email(user_input, token.token)
            logging.info('Sent token to %s', user_input)
            return redirect('/query')
        elif user_input.startswith('01') or user_input.startswith('00') or user_input.startswith('+'):
            phone_number = ''.join(c for c in user_input if c in '0123456789')
            if user_input.startswith('+'):
                phone_number = '+' + phone_number
            token = Token(token=generate_token(), requested_by=user_input)
            db.session.add(token)
            db.session.commit()
            logging.info('Sent token to %s', phone_number)
            send_token_by_sms(phone_number, token.token)
            return redirect('/query')
        logging.warning('Could not sent token to %s', user_input)
    return render_template('index.html', form=form)


@app.route('/query', methods=['GET', 'POST'])
def route_query():
    global max_total_query_requests
    form = RequestResultForm(request.form or request.args)
    token_expired = False
    token_not_found = False
    if form.validate_on_submit():
        logging.debug('Form validated, trying to access result %s with %s', form.code.data, form.token.data)
        if not max_total_query_requests:
            logging.error('Maximal number of query requests exhausted!')
            raise Exception('Maximal number of query requests exhausted!')
        max_total_query_requests -= 1
        token = Token.query.get(form.token.data.strip())
        if not token:
            logging.warning('Invalid token for result %s with %s: %s', form.code.data, form.token.data, token)
            token_not_found = 'Invalid token'
        elif token.used > 2 or (datetime.datetime.utcnow() - token.created_at).total_seconds() > app.config['TOKEN_LIFETIME_IN_SECONDS']:
            logging.warning('Token expired for result %s with %s: %s', form.code.data, form.token.data, token)
            token_expired = True
        else:
            # TODO: Move to configuration prior to commit
            code_input = form.code.data
            if 'CODE_CLEANUP' in app.config:
                code_input = app.config['CODE_CLEANUP'](code_input)
            result = Result.query.get(b'0' + hashlib.pbkdf2_hmac(app.config['PBKDF2_HASH_FUNCTION'], code_input.encode(), app.config['PEPPER'], app.config['PBKDF2_ROUNDS']))
            if result:
                db.session.add(Access(token=token.token, Result=result))
                logging.info('Providing result with hash %s and token %s', result.hash, token)
            else:
                logging.warning('No result found with %s and token %s', code_input, token)
            token.used += 1
            db.session.commit()
            return render_template('result.html', result=result, code=code_input, code_input=form.code.data.strip())
    else:
        logging.debug('Form not validated code: %s and token: %s', form.code.data, form.token.data)
    return render_template('query.html', form=form, token_expired=token_expired, token_not_found=token_not_found)


@app.route('/import', methods=['POST'])
def route_import():
    data = request.get_json(force=True)
    if data['API_KEY'] not in app.config['API_KEYS']:
        raise Forbidden()
    for row in data['ROWS']:
        skip = False
        for callback in app.config.get('IMPORT_PRE_PROCESSING', []):
            logging.log(5, 'Executing PRE callback %s', callback.__name__)
            skip |= callback(row, data) is False
        if skip:
            continue
        if 'hash_value' in row:
            row['hash_value'] = base64.b64decode(row['hash_value'])
        entry = Result.get_or_create(**row)
        logging.debug('Importing row with hash: %s', entry.hash)
        for callback in app.config.get('IMPORT_POST_PROCESSING', []):
            logging.log(5, 'Executing POST callback %s', callback.__name__)
            callback(row, entry, data)

    db.session.commit()
    return jsonify(STATUS='OK')


db.create_all()

if __name__ == '__main__':
    waitress.serve(app, host='127.0.0.1', port=5000 if len(sys.argv) < 2 else int(sys.argv[1]))

# TODO: QR code to scan code
