from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User
from django.db import transaction
from django.core.exceptions import ValidationError
from .models import Membership

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['username', 'email', 'is_verified', 'is_admin']

admin.site.register(User, CustomUserAdmin)

def assign_company(user, company, is_admin=False):
    if is_admin and user.companies.filter(membership__is_admin=True).exists:
        raise ValidationError('Only one admin per company')
    
    with transaction.atomic():
        Membership.objects.create(user=user, company=company, is_admin=is_admin)
        if is_admin:
            user.is_admin = True
            user.save()