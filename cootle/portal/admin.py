from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User
from django.db import transaction
from django.core.exceptions import ValidationError
from .models import Membership, Company, Invitation, Notification, DesignEffort, Mapping, Project, Purpose, ProjectEffort, ProjectEffortLink
from .forms import PurposeAdminForm, ProjectEffortAdminForm


class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['username', 'email', 'is_verified', 'is_admin']

admin.site.register(User, CustomUserAdmin)
admin.site.register(Company)
admin.site.register(Membership)
admin.site.register(Invitation)
admin.site.register(Notification)
admin.site.register(DesignEffort)
admin.site.register(Mapping)
admin.site.register(Project)

@admin.register(Purpose)
class PurposeAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'project', 'created_at', 'updated_at')
    search_fields = ('title', 'user__username', 'project__name')
    filter_horizontal = ('desired_outcomes', 'design_efforts')
    form = PurposeAdminForm

class ProjectEffortAdmin(admin.ModelAdmin):
    list_display = ('user', 'project', 'design_effort', 'outcome', 'purpose', 'local_id')
    search_fields = ('user__username', 'project__name', 'design_effort__title', 'outcome__title', 'purpose__title')
    list_filter = ('project', 'design_effort', 'outcome', 'purpose')

    # Custom form integration
    form = ProjectEffortAdminForm

    # Optionally, include inline editing for ProjectEffortLink
    class ProjectEffortLinkInline(admin.TabularInline):
        model = ProjectEffortLink
        extra = 1  # Number of extra inline forms to display

    inlines = [ProjectEffortLinkInline]

# Register the ProjectEffort model with the ProjectEffortAdmin class
admin.site.register(ProjectEffort, ProjectEffortAdmin)

def assign_company(user, company, is_admin=False):
    # Check if the user is already an admin in any company
    # if is_admin and Membership.objects.filter(user=user, is_admin=True).exists():
    #     raise ValidationError('A user can only be an admin for one company.')

    with transaction.atomic():
        # Create the membership record
        Membership.objects.create(user=user, company=company, is_admin=is_admin)
        if is_admin:
            # Update the user to reflect the admin status
            user.is_admin = True
            user.save()