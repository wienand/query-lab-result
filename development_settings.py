SECRET_KEY = b'J\xd5\x89&\x0eU\x86j\xadF\xd0&\xe1$\x84i'
PEPPER = b'v7\x1d\xf4\xca@\xc0;X\xa8"\xecj\x84\xd1\x9e'
BASE_URL = 'http://127.0.0.1:5000'
API_KEYS = ['f29b2b8947da9429a7716c51585e5c64c516a06ba708c97c9897a430df68f17d']
SMS_GATEWAY_EMAIL = '@sms.example.com'
SMTP_HOST = '127.0.0.1'
SMTP_FROM = 'laborergebnisse@example.com'
SMTP_ERROR_TO = ['devops@example.com']
SMTP_BCC = SMTP_ERROR_TO
SMTP_TOKEN_TEMPLATE = """From: %s
To: %s
Subject: Abrufcode Laborergebnisse

%s ist Ihr Abrufcode zu dem Laborergebnis auf %s/query?token=%s. Vielen Dank, Ihr Klinikum Stuttgart"""
