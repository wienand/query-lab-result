# Used for CSRF protection of wtforms (other than that, the session cookie is not used)
# give a random string, at best generated by import secrets; print(secrets.token_bytes(16))
SECRET_KEY = None

# Used to pepper the hashes of the identifier, just in case there is some information there
PEPPER = b'.\x02G\x04\xc39\xec\xdc1\xe3\xad\xc6\xc3\xec8\xe5'

# Base URL of the system, used in SMS and emails
BASE_URL = 'http://127.0.0.1:5000'

# Regular expression covering all allowed identifiers to access lab results (case insensitive)
CODE_REGEXP = r'^ *LAB-([A-Z\d] *){16} *$'

# API keys to push data to the system, i.e. ['1ed51a78b2959cbfd035aa6de641253355bcd91a509bf3806275aaa8388d9128']
# (do not use the super secret key as everyone can get it from Github now, generate your own with:
# import secrets; print(secrets.token_hex(32))
API_KEYS = []

# SMS are send via email to +..........@sms.example.com (user can enter +43..., 017... or 00...., default country is +49 Germany)
SMS_GATEWAY_EMAIL = '@sms.example.com'
# SMTP details
SMTP_HOST = '127.0.0.1'
SMTP_FROM = 'laborergebnisse@example.com'
SMTP_ERROR_TO = ['devops@example.com']
# All messages sent by regular operation, i.e. without the error messages, are BCCed to these addresses
SMTP_BCC = SMTP_ERROR_TO
# Message template, currently only all
SMTP_TOKEN_TEMPLATE = """From: {sender}
To: {to}
Subject: Abrufcode Laborergebnisse

{token} ist Ihr Abrufcode zu dem Laborergebnis auf {base_url}/query?token={token}. Vielen Dank, Ihr Klinikum Stuttgart"""
SMTP_NOTIFY_TEMPLATE = """From: {sender}
Subject: SMS Notification Lab Result

Sie können Ihr Laborergebnis unter {base_url} abrufen.
"""

# Used to normalize the code received from the user, after this it should match the code used to import the data (or used to create the hash)
def CODE_CLEANUP(code):
    # Harmonize input prior to hash generation for comparing to existing hashes
    return code.upper().strip()
