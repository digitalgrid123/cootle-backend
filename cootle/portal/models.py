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

    def generate_verification_code(self):
        self.verification_code = ''.join(random.choices(string.digits, k=6))
        self.save()
        return self.verification_code

class Company(models.Model):
    name = models.CharField(max_length=255, unique=True)
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
        unique_together = ('user', 'company', 'is_admin')