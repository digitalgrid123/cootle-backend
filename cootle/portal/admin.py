from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User
from django.db import transaction
from django.core.exceptions import ValidationError
from .models import Membership, Company


class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['username', 'email', 'is_verified', 'is_admin']

admin.site.register(User, CustomUserAdmin)
admin.site.register(Company)

def assign_company(user, company, is_admin=False):
    # Check if the user is already an admin in any company
    if is_admin and Membership.objects.filter(user=user, is_admin=True).exists():
        raise ValidationError('A user can only be an admin for one company.')

    with transaction.atomic():
        # Create the membership record
        Membership.objects.create(user=user, company=company, is_admin=is_admin)
        if is_admin:
            # Update the user to reflect the admin status
            user.is_admin = True
            user.save()