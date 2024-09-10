# phishing_email_Detector
import imaplib
import email
from email.parser import BytesParser
from email.policy import default
import csv
import re

def connect_to_email():
    email_address = "4mt21ic013@mite.ac.in"  # Replace with your email
    email_password = "$Disha1234"        # Replace with your password
    
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(email_address, email_password)
        return mail
    except imaplib.IMAP4.error as e:
        print(f"Failed to login: {e}")
        return None

def fetch_emails(mail):
    try:
        mail.select('inbox')
        status, messages = mail.search(None, 'ALL')
        email_ids = messages[0].split()
        return email_ids
    except Exception as e:
        print(f"Failed to fetch emails: {e}")
        return []

def analyze_email(raw_email):
    try:
        # Parse the email content
        email_message = BytesParser(policy=default).parsebytes(raw_email)
        body = email_message.get_body(preferencelist=('plain', 'html')).get_content()
        
        # Define suspicious phrases and regex patterns for phishing detection
        suspicious_phrases = ['urgent', 'click here', 'verify your account', 'winner', 'congratulations']
        patterns = [r'click\s*here', r'verify\s*your\s*account', r'urgent\s*action']
        
        # Check for suspicious phrases
        if any(phrase in body.lower() for phrase in suspicious_phrases):
            return 'Suspicious'
        
        # Check for regex patterns
        if any(re.search(pattern, body, re.IGNORECASE) for pattern in patterns):
            return 'Suspicious'
        
        return 'Legitimate'
    except Exception as e:
        print(f"Failed to analyze email: {e}")
        return 'Error'

def generate_report(results):
    try:
        with open('email_report.csv', 'w', newline='') as csvfile:
            fieldnames = ['Email', 'Subject', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow(result)
    except Exception as e:
        print(f"Failed to generate report: {e}")

def main():
    mail = connect_to_email()
    if mail is None:
        return
    
    email_ids = fetch_emails(mail)
    results = []

    for num in email_ids:
        try:
            status, data = mail.fetch(num, '(RFC822)')
            status = analyze_email(data[0][1])
            msg = email.message_from_bytes(data[0][1])
            results.append({'Email': msg['from'], 'Subject': msg['subject'], 'Status': status})
        except Exception as e:
            print(f"Failed to process email {num}: {e}")

    generate_report(results)
    mail.logout()

if __name__ == "__main__":
    main()
