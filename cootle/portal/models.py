from django.db import models, transaction
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
    
    def get_company_logo(self):
        return self.company.logo
    
class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.message
    
class Category(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class DesignEffort(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class Mapping(models.Model):
    class TypeChoices(models.TextChoices):
        OBJECTIVE = 'OBJ', 'Objective'
        VALUE = 'VAL', 'Value'
        OUTCOME = 'OUT', 'Outcome'

    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    design_efforts = models.ManyToManyField(DesignEffort, blank=True)
    type = models.CharField(max_length=3, choices=TypeChoices.choices)

    def __str__(self):
        return self.title
    
class Project(models.Model):
    name = models.CharField(max_length=255)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    
class Purpose(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    desired_outcomes = models.ManyToManyField(Mapping, blank=True)
    design_efforts = models.ManyToManyField(DesignEffort, blank=True)
    local_id = models.PositiveIntegerField(editable=False)

    def __str__(self):
        return self.title
    
    @transaction.atomic
    def save(self, *args, **kwargs):
        if not self.local_id:
            last_purpose = Purpose.objects.select_for_update().filter(project=self.project).order_by('local_id').last()
            if last_purpose:
                self.local_id = last_purpose.local_id + 1
            else:
                self.local_id = 1
        super(Purpose, self).save(*args, **kwargs)

class ProjectEffort(models.Model):
    class ValueStatus(models.TextChoices):
        YET_TO_BE_CHECKED = 'YBC', 'Yet to be checked',
        UNCHECKED = 'UCH', 'Unchecked',
        UNPLANNED_ACTIVITY = 'UPA', 'Unplanned Activity',
        REALISED = 'REA', 'Realised',
        VALUE_UNREALISED = 'VUR', 'Value Unrealised',        

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_project_efforts')
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    design_effort = models.ForeignKey(DesignEffort, on_delete=models.CASCADE)
    outcome = models.ForeignKey(Mapping, on_delete=models.CASCADE)
    purpose = models.ForeignKey(Purpose, on_delete=models.CASCADE)
    local_id = models.PositiveIntegerField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    value_status = models.CharField(max_length=3, choices=ValueStatus.choices, default=ValueStatus.YET_TO_BE_CHECKED)
    checked_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='checked_project_efforts', null=True, blank=True)
    checked_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.local_id:
            last_effort = ProjectEffort.objects.filter(project=self.project).order_by('local_id').last()
            if last_effort:
                self.local_id = last_effort.local_id + 1
            else:
                self.local_id = 1
        super(ProjectEffort, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.project.name} - {self.design_effort.title}"
    
class ProjectEffortLink(models.Model):
    project_effort = models.ForeignKey(ProjectEffort, on_delete=models.CASCADE, related_name='links')
    link = models.TextField()

    def __str__(self):
        return f"Link for {self.project_effort}"