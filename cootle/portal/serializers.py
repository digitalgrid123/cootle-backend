from rest_framework import serializers
from .models import User, Company, Invitation

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
        fields = ['fullname']


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = ['name', 'logo']
        extra_kwargs = {
            'name': {'required': True},
        }

class InvitationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['email', 'company']

class AcceptInvitationSerializer(serializers.Serializer):
    token = serializers.CharField()
    email = serializers.EmailField()