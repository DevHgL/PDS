import os
import pickle
import base64
import quopri
import joblib
from dotenv import load_dotenv
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Carrega as variáveis definidas no arquivo .env
load_dotenv()
GMAIL_CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE", "credentials.json")
GMAIL_TOKEN_FILE = os.getenv("GMAIL_TOKEN_FILE", "token.pickle")

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def gmail_authenticate():
    creds = None
    if os.path.exists(GMAIL_TOKEN_FILE):
        with open(GMAIL_TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(GMAIL_TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

def get_message_content(service, msg_id):
    message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = message.get('payload', {})
    parts = payload.get('parts', [])
    data = ""
    if parts:
        for part in parts:
            if part.get('mimeType') == 'text/plain':
                body = part.get('body', {}).get('data')
                if body:
                    data = base64.urlsafe_b64decode(body.encode('ASCII')).decode('utf-8', errors='ignore')
                    break
    else:
        body = payload.get('body', {}).get('data')
        if body:
            data = base64.urlsafe_b64decode(body.encode('ASCII')).decode('utf-8', errors='ignore')
    if data and '=' in data:
        data = quopri.decodestring(data).decode('utf-8', errors='ignore')
    return data

def fetch_emails(service, max_results=10):
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=max_results).execute()
    messages = results.get('messages', [])
    emails = []
    if messages:
        for msg in messages:
            email_text = get_message_content(service, msg['id'])
            if email_text:
                emails.append(email_text)
    return emails

def classify_emails(emails, model):
    for idx, email in enumerate(emails, 1):
        prediction = model.predict([email])
        result = "Possível phishing" if prediction[0] == 1 else "Email legítimo"
        print(f"Email {idx}: {result}")
        print("-" * 40)
        print(email[:300])
        print("\n")

def main():
    service = gmail_authenticate()
    print("Autenticado no Gmail com sucesso.")
    emails = fetch_emails(service, max_results=10)
    if not emails:
        print("Nenhum e-mail encontrado.")
        return
    print(f"Foram encontrados {len(emails)} e-mails para análise.\n")
    model = joblib.load('phishing_detection_model.pkl')
    print("Modelo de detecção de phishing carregado.\n")
    classify_emails(emails, model)

if __name__ == '__main__':
    main()
