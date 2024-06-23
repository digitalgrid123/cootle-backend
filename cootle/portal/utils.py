from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from email.mime.image import MIMEImage
from django.template.loader import render_to_string
import os
import json
from pathlib import Path
from .models import Company, Mapping, DesignEffort, Category

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
def load_default_mappings(company):
    """
    Load default mappings from a JSON file and create them in the database if they do not exist.
    """
    json_file_path = Path(__file__).resolve().parent / 'default_mappings.json'
    
    with open(json_file_path, 'r') as file:
        data = json.load(file)

    # Create default categories
    default_categories = data.get("default_categories", [])
    category_mapping = {}
    
    for category_data in default_categories:
        name = category_data.get('name')
        category, created = Category.objects.get_or_create(
            company=company,
            name=name
        )
        category_mapping[name] = category

    # Create default design efforts
    default_design_efforts = data.get("default_design_efforts", [])
    
    for effort_data in default_design_efforts:
        title = effort_data.get('title')
        description = effort_data.get('description')
        category_name = effort_data.get('category')
        category = category_mapping.get(category_name)
        
        if category:
            DesignEffort.objects.get_or_create(
                company=company,
                category=category,
                title=title,
                description=description
            )

    # Create default mappings
    default_mappings = data.get("default_mappings", [])
    
    for mapping_data in default_mappings:
        title = mapping_data.get('title')
        description = mapping_data.get('description')
        mapping_type = mapping_data.get('type')
        design_effort_titles = mapping_data.get('design_efforts', [])

        # Check if the mapping already exists
        if not Mapping.objects.filter(company=company, title=title, type=mapping_type).exists():
            # Create the mapping
            mapping = Mapping.objects.create(
                company=company,
                title=title,
                description=description,
                type=mapping_type
            )
            
            # Associate design efforts if any
            if design_effort_titles:
                for effort_title in design_effort_titles:
                    try:
                        effort = DesignEffort.objects.get(company=company, title=effort_title)
                        mapping.design_efforts.add(effort)
                    except DesignEffort.DoesNotExist:
                        print(f"Design effort '{effort_title}' does not exist for the company '{company}'.")

            mapping.save()