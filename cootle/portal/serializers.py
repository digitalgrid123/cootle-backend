from rest_framework import serializers
from .models import User, Company, Invitation, Notification, Category, DesignEffort, Mapping
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
        slug_field='name'
    )

    class Meta:
        model = DesignEffort
        fields = ['id', 'title', 'description', 'created_at', 'updated_at', 'category']
        extra_kwargs = {
            'title': {'required': True},
            'description': {'required': True},
            'category': {'required': True}
        }

    def create(self, validated_data):
        if not validated_data.get('title') or not validated_data.get('description') or not validated_data.get('category'):
            raise serializers.ValidationError("All fields are required for creating a DesignEffort.")
        return super().create(validated_data)

    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.description = validated_data.get('description', instance.description)
        instance.category = validated_data.get('category', instance.category)
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
        instance.title = validated_data.get('title', instance.title)
        instance.description = validated_data.get('description', instance.description)
        instance.type = instance.type
        
        if 'design_efforts' in validated_data:
            design_efforts = validated_data.pop('design_efforts')
            instance.design_efforts.set(design_efforts)

        instance.save()
        return instance
