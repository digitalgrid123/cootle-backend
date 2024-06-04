from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import random
import string

# Create your models here.

class User(AbstractUser):
    is_verified = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=6, blank=True, null=True)
    fullname = models.CharField(max_length=30, blank=True, null=True)  # Changed TextField to CharField
    profile_pic = models.ImageField(upload_to='images/profile-pics/', blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.fullname:
            self.fullname = f"User#{self.id if self.id else 'unknown'}"
        super(User, self).save(*args, **kwargs)

        # Update fullname again after the first save to get the actual id
        if self.fullname == f"User#unknown":
            self.fullname = f"User#{self.id}"
            super(User, self).save(update_fields=['fullname'])

    def generate_verification_code(self):
        self.verification_code = ''.join(random.choices(string.digits, k=6))
        self.save()
        return self.verification_code

class Company(models.Model):
    name = models.CharField(max_length=255, unique=True)
    logo = models.ImageField(upload_to='images/company-logos/', blank=True, null=True)
#     members = models.ManyToManyField(User, through='Membership')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name

class Membership(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
#     role = models.CharField(max_length=20, choices=(('member', 'Member'), ('admin', 'Admin')))
    is_admin = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ('user', 'company')


class Invitation(models.Model):
    email = models.EmailField()
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='invitations')
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)
    accepted_at = models.DateTimeField(null=True, blank=True)
    rejected = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.email} - {self.company.name}"