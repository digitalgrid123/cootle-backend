from django.core.mail import send_mail
from django.conf import settings

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
    message = f'Please use the following link to accept the invitation: ' \
              f'{frontend_url}?token={invitation.token}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [invitation.email]

    send_mail(subject, message, from_email, recipient_list)