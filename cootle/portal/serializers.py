from rest_framework import serializers
from .models import User, Company, Invitation, Notification, Category, DesignEffort, Mapping, Project, Purpose, ProjectEffort, ProjectEffortLink
from django.conf import settings

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'fullname', 'is_verified', 'is_admin', 'profile_pic']
        extra_kwargs = {
            'email': {'required': True},
            'fullname': {'required': True},
        }

class UserAccessSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email']
        extra_kwargs = {
            'email': {'required': True},
        }

class UserVerificationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    verification_code = serializers.CharField()
    class Meta:
        model = User
        fields = ['email', 'verification_code']
        extra_kwargs = {
            'email': {'required': True},
            'verification_code': {'required': True},
        }

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['fullname', 'profile_pic']


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = ['id', 'name', 'logo']
        extra_kwargs = {
            'name': {'required': True},
        }

class InvitationSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.name', read_only=True)
    invite_email = serializers.CharField(source='invited_by.email', read_only=True)

    class Meta:
        model = Invitation
        fields = ['email', 'company', 'company_name', 'invited_by', 'invite_email', 'created_at']
        read_only_fields = ['company_name', 'invite_email']

class InvitationListSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.name', read_only=True)
    invited_by_email = serializers.CharField(source='invited_by.email', read_only=True)
    invited_user_fullname = serializers.SerializerMethodField()
    invited_user_profile_pic = serializers.SerializerMethodField()
    invited_user_id = serializers.SerializerMethodField()

    class Meta:
        model = Invitation
        fields = ['email', 'company', 'company_name', 'invited_by', 'invited_by_email', 'created_at', 'accepted', 'accepted_at', 'rejected', 'invited_user_id', 'invited_user_fullname', 'invited_user_profile_pic']
        read_only_fields = ['company_name', 'invited_by_email', 'invited_user_id', 'invited_user_fullname', 'invited_user_profile_pic']

    def get_invited_user_fullname(self, obj):
        user = User.objects.filter(email=obj.email).first()
        return user.fullname if user else None

    def get_invited_user_profile_pic(self, obj):
        user = User.objects.filter(email=obj.email).first()
        return f"{settings.BASE_URL}{user.profile_pic.url}" if user and user.profile_pic else None
    
    def get_invited_user_id(self, obj):
        user = User.objects.filter(email=obj.email).first()
        return user.id if user else None


class AcceptEmailInvitationSerializer(serializers.Serializer):
    token = serializers.CharField()
    email = serializers.EmailField()

class AcceptInvitationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['company']
        extra_kwargs = {
            'company': {'required': True},
        }
    
    def validate(self, data):
        # Add email from context (request user) to validated data
        data['email'] = self.context['request'].user.email
        return data
    

class NotificationSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Notification
        fields = ['id', 'user', 'message', 'created_at', 'is_read']

    def create(self, validated_data):
        return Notification.objects.create(**validated_data)
    
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', 'created_at', 'updated_at']
        extra_kwargs = {
            'name': {'required': True},
        }

class DesignEffortSerializer(serializers.ModelSerializer):
    category = serializers.SlugRelatedField(
        queryset=Category.objects.all(),
        slug_field='name',
        required=False
    )
    category_id = serializers.PrimaryKeyRelatedField(
        queryset=Category.objects.all(),
        write_only=True,  # Ensures this field is not included in serialized output
        required=True
    )

    class Meta:
        model = DesignEffort
        fields = ['id', 'title', 'description', 'created_at', 'updated_at', 'category', 'category_id']
        read_only_fields = ['category']
        extra_kwargs = {
            'title': {'required': True},
            'description': {'required': True},
            'category_id': {'required': True},  # Allow category to be optional in input
        }

    def create(self, validated_data):
        category_id = validated_data.pop('category_id')
        category = Category.objects.get(id=category_id)
        design_effort = DesignEffort.objects.create(category=category, **validated_data)
        return design_effort

    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        return instance


class MappingSerializer(serializers.ModelSerializer):
    design_efforts = serializers.PrimaryKeyRelatedField(
        queryset=DesignEffort.objects.all(),
        many=True,
        required=False
    )

    class Meta:
        model = Mapping
        fields = ['id', 'title', 'description', 'created_at', 'updated_at', 'design_efforts', 'type']
        extra_kwargs = {
            'title': {'required': True},
            'description': {'required': True},
            'type': {'required': True}
        }

    def create(self, validated_data):
        design_efforts = validated_data.pop('design_efforts', [])
        mapping = Mapping.objects.create(**validated_data)
        mapping.design_efforts.set(design_efforts)
        return mapping

    def update(self, instance, validated_data):
        instance.title = instance.title
        instance.description = validated_data.get('description', instance.description)
        instance.type = instance.type

        instance.save()
        return instance

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ['id', 'name', 'created_at', 'updated_at']
        extra_kwargs = {
            'name': {'required': True}
        }

class PurposeSerializer(serializers.ModelSerializer):
    desired_outcomes = serializers.PrimaryKeyRelatedField(
        queryset=Mapping.objects.filter(type='OUT'), many=True, required=False
    )
    design_efforts = serializers.PrimaryKeyRelatedField(
        queryset=DesignEffort.objects.all(), many=True, required=False
    )
    project = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all(), required=False)

    class Meta:
        model = Purpose
        fields = ['id', 'local_id', 'title', 'description', 'project', 'created_at', 'updated_at', 'desired_outcomes', 'design_efforts']
        extra_kwargs = {
            'title': {'required': True},
            'description': {'required': True}
        }

    def create(self, validated_data):
        desired_outcomes = validated_data.pop('desired_outcomes', [])
        design_efforts = validated_data.pop('design_efforts', [])
        purpose = Purpose.objects.create(**validated_data)
        purpose.desired_outcomes.set(desired_outcomes)
        purpose.design_efforts.set(design_efforts)
        return purpose
    
    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.description = validated_data.get('description', instance.description)
        instance.project = instance.project

        if 'desired_outcomes' in validated_data:
            desired_outcomes = validated_data.pop('desired_outcomes')
            instance.desired_outcomes.set(desired_outcomes)
        
        if 'design_efforts' in validated_data:
            design_efforts = validated_data.pop('design_efforts')
            instance.design_efforts.set(design_efforts)
        
        instance.save()
        return instance

class ProjectEffortLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectEffortLink
        fields = ['id', 'link']

class ProjectEffortSerializer(serializers.ModelSerializer):
    outcome = serializers.PrimaryKeyRelatedField(
        queryset=Mapping.objects.filter(type='OUT'), required=False
    )
    links = ProjectEffortLinkSerializer(many=True, required=False)
    project = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all(), required=False)
    

    class Meta:
        model = ProjectEffort
        fields = ['id', 'project', 'created_at', 'updated_at', 'design_effort', 'outcome', 'purpose', 'local_id', 'links']
        read_only_fields = ['id', 'local_id', 'created_at', 'updated_at']

    def create(self, validated_data):
        links_data = validated_data.pop('links', [])
        project_effort = ProjectEffort.objects.create(**validated_data)

        # Create related ProjectEffortLink instances
        for link_data in links_data:
            ProjectEffortLink.objects.create(project_effort=project_effort, **link_data)
        return project_effort

    def update(self, instance, validated_data):
        links_data = validated_data.pop('links', [])
        instance.design_effort = validated_data.get('design_effort', instance.design_effort)
        instance.outcome = validated_data.get('outcome', instance.outcome)
        instance.purpose = validated_data.get('purpose', instance.purpose)
        instance.save()

        # Update links
        instance.links.all().delete()
        for link_data in links_data:
            ProjectEffortLink.objects.create(project_effort=instance, **link_data)

        return instance