from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from email.mime.image import MIMEImage
from django.template.loader import render_to_string
import os

def send_verification_email(email, code):
    subject = 'Your Verification Code'
    message = f'Your verification code is {code}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

def send_login_email(email, code):
    subject = 'Your Login Code'
    message = f'Your login code is {code}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

def send_invitation_email(invitation):
    subject = 'You are invited to join a company'
    frontend_url = 'http://localhost:3000/signup'
    message = render_to_string('invitation_email.html', {
        'frontend_url': frontend_url,
        'company_name': invitation.company.name,
        'company_logo_url': invitation.company.logo.url if invitation.company.logo else None
    })
    
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [invitation.email]
    
    email = EmailMessage(subject, message, from_email, recipient_list)
    email.content_subtype = 'html'  # Set the content to HTML

    # Attach the company logo if it exists and is accessible
    if invitation.company.logo and os.path.isfile(invitation.company.logo.path):
        try:
            with open(invitation.company.logo.path, 'rb') as logo:
                mime_logo = MIMEImage(logo.read())
                mime_logo.add_header('Content-ID', '<company_logo>')
                email.attach(mime_logo)
        except IOError:
            # Log an error or handle it as needed
            pass

    email.send()

def send_invitation_message(invitation):
    subject = 'You were invited to join a company'
    message = render_to_string('invitation_message.html', {
        'company_name': invitation.company.name,
        'company_logo_url': invitation.company.logo.url if invitation.company.logo else None
    })

    from_email = settings.EMAIL_HOST_USER
    recipient_list = [invitation.email]

    email = EmailMessage(subject, message, from_email, recipient_list)
    email.content_subtype = 'html'  # Set the content to HTML

    # Attach the company logo if it exists and is accessible
    if invitation.company.logo and os.path.isfile(invitation.company.logo.path):
        try:
            with open(invitation.company.logo.path, 'rb') as logo:
                mime_logo = MIMEImage(logo.read())
                mime_logo.add_header('Content-ID', '<company_logo>')
                email.attach(mime_logo)
        except IOError:
            # Log an error or handle it as needed
            pass