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
    class Meta:
        model = Invitation
        fields = ['email', 'company', 'invited_by', 'created_at', 'accepted', 'accepted_at', 'rejected']

class AcceptEmailInvitationSerializer(serializers.Serializer):
    token = serializers.CharField()
    email = serializers.EmailField()

class AcceptInvitationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['email', 'company']
        extra_kwargs = {
            'email': {'required': True},
            'company': {'required': True},
        }