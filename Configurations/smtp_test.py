import smtplib
from email.mime.text import MIMEText

# Sender and recipient email addresses
sender_email = ""
receiver_email = ""
password = " "  # Use App Password if 2FA is enabled

# Email content
subject = "Sample Email from Grok"
body = "Hello! This is a test email sent using Python and SMTP."
msg = MIMEText(body)
msg["Subject"] = subject
msg["From"] = sender_email
msg["To"] = receiver_email

try:
    # Connect to Gmail's SMTP server
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()  # Enable TLS
    server.login(sender_email, password)  # Login to the server
    server.sendmail(sender_email, receiver_email, msg.as_string())  # Send the email
    server.quit()  # Close the connection
    print("Email sent successfully!")
except Exception as e:
    print(f"Failed to send email: {e}")