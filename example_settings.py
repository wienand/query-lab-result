SECRET_KEY = b':k\xab\x01!\x99\xaa~~\x8d\xdb\xd5W\x98\x9e\xd6'
PEPPER = b'.\x02G\x04\xc39\xec\xdc1\xe3\xad\xc6\xc3\xec8\xe5'
BASE_URL = 'http://127.0.0.1:5000'
CODE_REGEXP = r'^ *((([A-Za-z0-9-] *){36})|((EDTA *)?(\d *){8})|((EDTA *)?(\d *){10} *)) *$'
API_KEYS = ['1ed51a78b2959cbfd035aa6de641253355bcd91a509bf3806275aaa8388d9128']
SMS_GATEWAY_EMAIL = '@sms.example.com'
SMTP_HOST = '127.0.0.1'
SMTP_FROM = 'laborergebnisse@example.com'
SMTP_ERROR_TO = ['devops@example.com']
SMTP_BCC = SMTP_ERROR_TO
SMTP_TOKEN_TEMPLATE = """From: %s
To: %s
Subject: Abrufcode Laborergebnisse

%s ist Ihr Abrufcode zu dem Laborergebnis auf %s/query?token=%s. Vielen Dank, Ihr Klinikum Stuttgart"""


def CODE_CLEANUP(code):
    # Harmonize input prior to hash generation for comparing to existing hashes
    return code.upper().strip()
