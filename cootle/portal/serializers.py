from rest_framework import serializers
from .models import User, Company, Invitation

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'fullname', 'is_verified', 'is_admin', 'profile_pic']
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

    class Meta:
        model = Invitation
        fields = ['email', 'company', 'company_name', 'invited_by', 'invited_by_email', 'created_at', 'accepted', 'accepted_at', 'rejected', 'invited_user_fullname', 'invited_user_profile_pic']
        read_only_fields = ['company_name', 'invited_by_email', 'invited_user_fullname', 'invited_user_profile_pic']

    def get_invited_user_fullname(self, obj):
        user = User.objects.filter(email=obj.email).first()
        return user.fullname if user else None

    def get_invited_user_profile_pic(self, obj):
        user = User.objects.filter(email=obj.email).first()
        return user.profile_pic.url if user and user.profile_pic else None


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