import json
from pathlib import Path
from django.shortcuts import render, get_object_or_404
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.views import View
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework import status, generics, serializers
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .permissions import IsAdminUser
from .models import User, Company, Invitation, Membership, Notification, Category, DesignEffort, Mapping, Project, Purpose, ProjectEffort, ProjectEffortLink
from .serializers import UserSerializer, UserAccessSerializer, UserVerificationSerializer, UserUpdateSerializer, CompanySerializer, InvitationSerializer, InvitationListSerializer, AcceptEmailInvitationSerializer, AcceptInvitationSerializer, NotificationSerializer, CategorySerializer, DesignEffortSerializer, MappingSerializer, ProjectSerializer, PurposeSerializer, ProjectEffortSerializer, ProjectEffortLinkSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .utils import send_verification_email, send_login_email, send_invitation_email, send_invitation_message
from .admin import assign_company
from django.db.models.signals import post_save
from django.dispatch import receiver
from .utils import load_default_mappings
from datetime import datetime

# Create your views here.


def set_session(request):
    request.session['current_company_id'] = 1  # Set session data
    return HttpResponse("Session data set")


def get_session(request):
    current_company_id = request.session.get(
        'current_company_id', 'Not set')  # Get session data
    return HttpResponse(f"Current company ID: {current_company_id}")


def delete_session(request):
    try:
        del request.session['current_company_id']
    except KeyError:
        pass
    return HttpResponse("Session data deleted")

@ensure_csrf_cookie
def csrf_token(request):
    return JsonResponse({'csrfToken': request.META.get('CSRF_COOKIE')})

@receiver(post_save, sender=Company)
def create_default_mappings(sender, instance, created, **kwargs):
    if created:
        load_default_mappings(instance)

class DefaultMappingsView(APIView):
    permission_classes = [AllowAny]  # Allow access to all users

    def get_default_data(self):
        json_file_path = Path(__file__).resolve().parent / 'default_mappings.json'
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        return data

    def get(self, request, *args, **kwargs):
        json_file_path = Path(__file__).resolve().parent / 'default_mappings.json'
        if not json_file_path.exists():
            return Response({'status': 'JSON file does not exist'}, status=status.HTTP_404_NOT_FOUND)

        with open(json_file_path, 'r') as file:
            data = json.load(file)

        return Response(data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        if 'json_file' not in request.FILES:
            return Response({'status': 'JSON file is required'}, status=status.HTTP_400_BAD_REQUEST)

        json_file = request.FILES['json_file']
        try:
            file_content = json_file.read()
            data = json.loads(file_content)
            json_file_path = Path(__file__).resolve().parent / 'default_mappings.json'
            with open(json_file_path, 'w') as file:
                json.dump(data, file, indent=4)
            return Response({'status': 'JSON file uploaded successfully'}, status=status.HTTP_200_OK)
        except json.JSONDecodeError:
            return Response({'status': 'Invalid JSON file'}, status=status.HTTP_400_BAD_REQUEST)

class ResetMappingDataView(APIView):
    permission_classes = [IsAuthenticated]

    def get_default_data(self):
        json_file_path = Path(__file__).resolve().parent / 'default_mappings.json'
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        return data

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        company_id = request.session.get('current_company_id')
        if not company_id:
            return JsonResponse({'status': 'No company selected'}, status=400)

        try:
            company = Company.objects.get(id=company_id)
            if not Membership.objects.filter(company=company, user=request.user, is_admin=True).exists():
                return JsonResponse({'status': 'Permission denied'}, status=403)
            data = self.get_default_data()

            # Clear existing data
            Category.objects.filter(company=company).delete()
            DesignEffort.objects.filter(company=company).delete()
            Mapping.objects.filter(company=company).delete()

            # Create default categories
            categories = {}
            for category_data in data.get('default_categories', []):
                category = Category.objects.create(
                    company=company,
                    name=category_data['name']
                )
                categories[category.name] = category

            # Create default design efforts
            design_efforts = {}
            for effort_data in data.get('default_design_efforts', []):
                category_name = effort_data['category']
                category = categories.get(category_name)
                if category:
                    effort = DesignEffort.objects.create(
                        company=company,
                        category=category,
                        title=effort_data['title'],
                        description=effort_data['description']
                    )
                    design_efforts[effort.title] = effort

            # Create default mappings
            for mapping_data in data.get('default_mappings', []):
                mapping = Mapping.objects.create(
                    company=company,
                    title=mapping_data['title'],
                    description=mapping_data['description'],
                    type=mapping_data['type']
                )
                for effort_title in mapping_data.get('design_efforts', []):
                    effort = design_efforts.get(effort_title)
                    if effort:
                        mapping.design_efforts.add(effort)
                mapping.save()

            return JsonResponse({'status': 'Company data reset to default'}, status=200)

        except Company.DoesNotExist:
            return JsonResponse({'status': 'Company does not exist'}, status=404)

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserAccessSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user with email",
        responses={200: "Verification code sent to your email."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user, created = User.objects.get_or_create(email=email, username=email)
        if not created:
            return Response({'status': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if created or not user.is_verified:
            code = user.generate_verification_code()
            send_verification_email(email, code)

        return Response({'status': 'Verification code sent to your email'}, status=status.HTTP_201_CREATED)


class UserVerificationView(generics.GenericAPIView):
    serializer_class = UserVerificationSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify a user with email and verification code",
        responses={
            200: "Email verified successfully.",
            400: "Invalid verification code."
        },
        manual_parameters=[
            openapi.Parameter('email', openapi.IN_QUERY,
                              description="Email of the user", type=openapi.TYPE_STRING),
            openapi.Parameter('verification_code', openapi.IN_QUERY,
                              description="Verification code sent to the email", type=openapi.TYPE_STRING),
        ]
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        verification_code = serializer.validated_data['verification_code']
        user = User.objects.get(email=email)

        if user.verification_code == verification_code:
            user.is_verified = True
            user.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'status': 'User verified',
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }, status=status.HTTP_200_OK)
        else:
            return Response({'status': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(generics.GenericAPIView):
    serializer_class = UserAccessSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Login a user with email",
        responses={
            200: "User logged in successfully.",
            400: "Invalid email."
        },
        manual_parameters=[
            openapi.Parameter('email', openapi.IN_QUERY,
                              description="Email of the user", type=openapi.TYPE_STRING),
        ]
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        if user:
            if user.is_verified:

                code = user.generate_verification_code()
                send_login_email(email, code)

                return Response({'status': 'Login code sent to your email'}, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'User is not verified'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'status': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginVerificationView(generics.GenericAPIView):
    serializer_class = UserVerificationSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify a user with email and login code",
        responses={
            200: "User logged in successfully.",
            400: "Invalid login code."
        },
        manual_parameters=[
            openapi.Parameter('email', openapi.IN_QUERY,
                              description="Email of the user", type=openapi.TYPE_STRING),
            openapi.Parameter('verification_code', openapi.IN_QUERY,
                              description="Login code sent to the email", type=openapi.TYPE_STRING),
        ]
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        verification_code = serializer.validated_data['verification_code']
        user = User.objects.get(email=email)

        if user.verification_code == verification_code:
            refresh = RefreshToken.for_user(user)
            return Response({
                'status': 'User logged in successfully',
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }, status=status.HTTP_200_OK)
        else:
            return Response({'status': 'Invalid login code'}, status=status.HTTP_400_BAD_REQUEST)

# class UserLogoutView(generics.GenericAPIView):
#     permission_classes = [IsAuthenticated]

#     @swagger_auto_schema(
#         operation_description="Logout the user",
#         responses={200: "User logged out successfully."}
#     )
#     def post(self, request, *args, **kwargs):
#         try:
#             refresh_token = request.data["refresh"]
#             token = RefreshToken(refresh_token)
#             token.blacklist()

#             return Response({'status': 'User logged out successfully'}, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({'status': 'Error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer

    @swagger_auto_schema(
        operation_description="Update the user's fullname",
        responses={200: "User updated successfully."}
    )
    def put(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'status': 'User updated successfully'}, status=status.HTTP_200_OK)


class UserInfoView(generics.GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the user's info",
        responses={200: "User info."}
    )
    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DashboardInfoView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the user's dashboard info",
        responses={200: "Dashboard info."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            company_serializer = CompanySerializer(company)
            user = request.user
            return Response({
                'status': 'Dashboard info',
                'user': user.fullname,
                'email': user.email,
                'profile_pic': user.profile_pic.url if user.profile_pic else None,
                'company': company_serializer.data
            }, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class InviteUserView(generics.CreateAPIView):
    serializer_class = InvitationSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Invite new users to a company",
        responses={201: "Invitations sent successfully."}
    )
    def post(self, request, *args, **kwargs):
        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if the user is an admin of the current company
            company = Company.objects.get(id=current_company_id)
            membership = user.membership_set.get(
                company=company, is_admin=True)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Membership.DoesNotExist:
            return Response({'status': 'User is not an admin of the selected company'}, status=status.HTTP_403_FORBIDDEN)

        # Extract and validate emails from the request
        emails = request.data.get('emails', '')
        if not emails:
            return Response({'status': 'Emails field is required'}, status=status.HTTP_400_BAD_REQUEST)

        email_list = [email.strip() for email in emails.split(',')]
        invalid_emails = [
            email for email in email_list if not serializers.EmailField().run_validation(email)]

        if invalid_emails:
            return Response({'status': 'Invalid emails', 'invalid_emails': invalid_emails}, status=status.HTTP_400_BAD_REQUEST)

        invitations = []
        for email in email_list:
            if Membership.objects.filter(company=company, user__email=email).exists():
                return Response({'status': f'{email} is already a member of the company'}, status=status.HTTP_400_BAD_REQUEST)
            if Invitation.objects.filter(company=company, email=email).exists():
                return Response({'status': f'{email} has already been invited to the company'}, status=status.HTTP_400_BAD_REQUEST)
            invitation_data = {
                'email': email,
                'company': company.pk,
                'invited_by': user.pk
            }

            serializer = self.get_serializer(data=invitation_data)
            serializer.is_valid(raise_exception=True)
            invitation = serializer.save()
            invitation.token = get_random_string(length=32)
            invitation.save()
            if User.objects.filter(email=email).exists():
                send_invitation_message(invitation)
                user_instance = User.objects.get(email=email)
                notification_data = {
                    'user': user_instance.id,
                    'message': f"You have been invited to join {company.name}",
                    'created_at': timezone.now()
                }
                notification_serializer = NotificationSerializer(
                    data=notification_data)
                if notification_serializer.is_valid():
                    notification_serializer.save()
                else:
                    return Response(notification_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                send_invitation_email(invitation)
            invitations.append(invitation)

        return Response({'status': 'Invitations sent successfully', 'invitations': [inv.email for inv in invitations]}, status=status.HTTP_201_CREATED)


class AcceptEmailInvitationView(generics.GenericAPIView):
    serializer_class = AcceptEmailInvitationSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Accept an invitation to join a company",
        responses={200: "Invitation accepted successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']

        try:
            invitation = Invitation.objects.get(token=token, accepted=False)
        except Invitation.DoesNotExist:
            raise ValidationError('Invalid or expired token.')

        email = invitation.email  # Fetch email from the invitation object

        # Create a unique username
        base_username = email.split('@')[0]
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        user, created = User.objects.get_or_create(
            email=email, defaults={'username': username})
        if created:
            user.is_verified = True
            user.save()

        with transaction.atomic():
            invitation.accepted = True
            invitation.accepted_at = timezone.now()
            invitation.save()
            assign_company(user, invitation.company, is_admin=False)

        # Generate a passcode or verification code
        code = user.generate_verification_code()
        send_verification_email(email, code)  # Send the passcode via email

        return Response({'status': 'Invitation accepted successfully'}, status=status.HTTP_200_OK)


class AcceptInvitationView(generics.GenericAPIView):
    serializer_class = AcceptInvitationSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Accept an invitation to join a company",
        responses={200: "Invitation accepted successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company = serializer.validated_data['company']
        email = serializer.validated_data['email']

        try:
            invitation = Invitation.objects.get(
                email=email, company=company, accepted=False)
        except Invitation.DoesNotExist:
            raise ValidationError('Invalid or expired invitation.')

        user = request.user

        # Check if the user is already a member of the company
        if Membership.objects.filter(user=user, company=company).exists():
            return Response({'status': 'User is already a member of the company'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            invitation.accepted = True
            invitation.accepted_at = timezone.now()
            invitation.save()
            assign_company(user, company, is_admin=False)
            membership = Membership.objects.get(company=company, is_admin=True)
            notification_data = {
                'user': membership.user.id,
                'message': f"{user.fullname} has accepted the invitation to join {company.name}",
                'created_at': timezone.now()
            }
            notification_serializer = NotificationSerializer(
                data=notification_data)
            if notification_serializer.is_valid():
                notification_serializer.save()
            else:
                return Response(notification_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Send WebSocket notification for invitation accepted
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'invitations', {
                    'type': 'invitation_message',
                    'message': f'{request.user.fullname} has accepted the invitation to join {company.name}',
                    'event_type': 'invitation_accepted'
                }
            )

        return Response({'status': 'Invitation accepted successfully'}, status=status.HTTP_200_OK)


class RejectInvitationView(generics.GenericAPIView):
    serializer_class = AcceptInvitationSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Reject an invitation to join a company",
        responses={200: "Invitation rejected successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company = serializer.validated_data['company']
        email = serializer.validated_data['email']

        try:
            invitation = Invitation.objects.get(
                email=email, company=company, accepted=False)
        except Invitation.DoesNotExist:
            raise ValidationError('Invalid or expired invitation.')

        user = request.user
        # Check if the user is already a member of the company
        if Membership.objects.filter(user=user, company=company).exists():
            return Response({'status': 'User is already a member of the company'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            invitation.rejected = True
            invitation.save()
            membership = Membership.objects.get(company=company, is_admin=True)
            notification_data = {
                'user': membership.user.id,
                'message': f"{user.fullname} has rejected the invitation to join {company.name}",
                'created_at': timezone.now()
            }
            notification_serializer = NotificationSerializer(
                data=notification_data)
            if notification_serializer.is_valid():
                notification_serializer.save()
            else:
                return Response(notification_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            # Send WebSocket notification for invitation accepted
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'invitations', {
                    'type': 'invitation_message',
                    'message': f'{request.user.fullname} has rejected the invitation to join {company.name}',
                    'event_type': 'invitation_rejected'
                }
            )

        return Response({'status': 'Invitation rejected successfully'}, status=status.HTTP_200_OK)


class InvitationListView(generics.ListAPIView):
    serializer_class = InvitationSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all invitations for a user",
        responses={200: "List of invitations."}
    )
    def get(self, request, *args, **kwargs):
        user = request.user
        invitations = Invitation.objects.filter(
            email=user.email
        ).exclude(
            Q(accepted=True) | Q(rejected=True)
        )
        serializer = self.get_serializer(invitations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ListInvitationsView(generics.ListAPIView):
    serializer_class = InvitationListSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List invitations sent by the logged-in user from the current company",
        responses={200: InvitationListSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            if user.membership_set.filter(company=company, is_admin=True).exists():
                invitations = Invitation.objects.filter(
                    company=company, invited_by=user)
                serializer = self.get_serializer(invitations, many=True)
                response_data = {
                    'user': {
                        'fullname': user.fullname,
                        'email': user.email,
                        'profile_pic': f"{settings.BASE_URL}{user.profile_pic.url}" if user.profile_pic else None
                    },
                    'invitations': serializer.data
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'User is not an admin of this company'}, status=status.HTTP_403_FORBIDDEN)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class CreateCompanyView(generics.CreateAPIView):
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new company",
        responses={200: "Company created successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company = serializer.save()
        assign_company(request.user, company, is_admin=True)
        request.session['current_company_id'] = company.id
        session_id = request.session.session_key
        is_admin = True
        return Response({'status': 'Company created successfully', 'session_id': session_id, 'is_admin': is_admin}, status=status.HTTP_201_CREATED)


class SetCurrentCompanyView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Set the current company for a user",
        responses={
            200: "Current company set successfully.",
            400: "Company ID is required.",
            403: "User is not an admin of this company.",
            404: "Company does not exist."
        }
    )
    def post(self, request, *args, **kwargs):
        company_id = request.data.get('company_id')
        if not company_id:
            return Response({'status': 'Company ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=company_id)
            if request.user.membership_set.filter(company=company).exists():
                request.session['current_company_id'] = company_id
                request.session.save()
                session_id = request.session.session_key
                membership = request.user.membership_set.get(company=company)
                is_admin = membership.is_admin
                return Response({'status': 'Current company set successfully', 'session_id': session_id, 'is_admin': is_admin}, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'User is not a member of this company'}, status=status.HTTP_403_FORBIDDEN)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class EditCompanyView(generics.UpdateAPIView):
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Edit a company",
        responses={200: "Company updated successfully."}
    )
    def put(self, request, *args, **kwargs):
        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            membership = user.membership_set.get(
                company=company, is_admin=True)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Membership.DoesNotExist:
            raise ValidationError(
                'User is not associated with the selected company.')

        serializer = self.get_serializer(company, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'status': 'Company updated successfully'}, status=status.HTTP_200_OK)


class CompanyListView(generics.ListAPIView):
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all companies for a user",
        responses={200: "List of companies."}
    )
    def get(self, request, *args, **kwargs):
        user = request.user
        companies = Company.objects.filter(membership__user=user)
        serializer = self.get_serializer(companies, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CompanyMembersView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all members of the current company",
        responses={200: "List of members."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            # Ensure the user is an admin of the company
            if not company.membership_set.filter(user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            members = company.membership_set.filter(is_admin=False)
            users = [membership.user for membership in members]  # Extract User instances
            serializer = self.get_serializer(users, many=True)  # Serialize User instances
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class RemoveMemberView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Remove a member from the current company",
        responses={200: "Member removed successfully."}
    )
    def delete(self, request, *args, **kwargs):

        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        member_id = request.data.get('member_id')
        if not member_id:
            return Response({'status': 'Member ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            if not Membership.objects.filter(company=company, user=user, is_admin=True).exists():
                return Response({'status': 'User is not an admin of the selected company'}, status=status.HTTP_403_FORBIDDEN)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)

        try:
            member_to_remove = Membership.objects.get(
                user__id=member_id, company=company)
            member_to_remove.delete()

            # Also delete any invitations for this member and company
            invitations_to_remove = Invitation.objects.filter(
                email=member_to_remove.user.email, company=company)
            invitations_to_remove.delete()

            # channel_layer = get_channel_layer()
            # async_to_sync(channel_layer.group_send)(
            #     'members', {
            #         'type': 'member_message',
            #         'message': f'{member_to_remove.user.fullname} has been removed from {company.name}',
            #         'event_type': 'member_removed'
            #     }
            # )

            return Response({'status': 'Member and their invitations removed successfully'}, status=status.HTTP_200_OK)
        except Membership.DoesNotExist:
            return Response({'status': 'Member not found in the company'}, status=status.HTTP_404_NOT_FOUND)


class NotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all notifications for a user",
        responses={200: "List of notifications."}
    )
    def get(self, request, *args, **kwargs):
        user = request.user
        notifications = Notification.objects.filter(user=user)
        serializer = self.get_serializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MarkReadNotifications(generics.GenericAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Mark all notifications as read",
        responses={200: "Notifications marked as read successfully."}
    )
    def post(self, request, *args, **kwargs):
        user = request.user
        notifications = Notification.objects.filter(user=user)
        notifications.update(is_read=True)
        return Response({'status': 'Notifications marked as read successfully'}, status=status.HTTP_200_OK)


class RemoveNotificationView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Remove a notification",
        responses={200: "Notification removed successfully."}
    )
    def delete(self, request, *args, **kwargs):
        user = request.user
        notification_id = request.data.get('notification_id')
        if not notification_id:
            return Response({'status': 'Notification ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            notification = Notification.objects.get(
                id=notification_id, user=user)
            notification.delete()
            return Response({'status': 'Notification removed successfully'}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({'status': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)


class RemoveAllNotificationsView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Remove all notifications",
        responses={200: "All notifications removed successfully."}
    )
    def delete(self, request, *args, **kwargs):
        user = request.user
        notifications = Notification.objects.filter(user=user)
        notifications.delete()
        return Response({'status': 'All notifications removed successfully'}, status=status.HTTP_200_OK)


class CategoryListView(generics.ListAPIView):
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all categories for the current company",
        responses={200: "List of categories."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            if not Membership.objects.filter(company=company, user=request.user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            categories = company.category_set.all()
            serializer = self.get_serializer(categories, many=True)

            # Fetch design efforts associated with the first category
            first_category = categories.first()
            design_efforts = DesignEffort.objects.filter(
                category=first_category)
            design_efforts_data = DesignEffortSerializer(
                design_efforts, many=True).data

            # Add design efforts data to the response
            serializer.data[0]['design_efforts'] = design_efforts_data

            return Response(serializer.data, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class CreateCategoryView(generics.CreateAPIView):
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new category",
        responses={201: "Category created successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            if not Membership.objects.filter(company=company, user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            category = serializer.save(company=company)
            return Response({'status': 'Category created successfully', 'id': category.id}, status=status.HTTP_201_CREATED)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class CategoryDetailView(generics.ListAPIView):
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve design efforts associated with a category",
        responses={200: "List of design efforts associated with the category."},
    )
    def get(self, request, *args, **kwargs):
        # Retrieve the category ID from the URL parameters
        category_id = self.kwargs.get('category_id')
        if not category_id:
            return Response({'status': 'Category ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the category instance using the ID
        category = Category.objects.filter(pk=category_id).first()

        if category:

            current_company_id = request.session.get('current_company_id')
            if not current_company_id:
                return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                company = Company.objects.get(id=current_company_id)
                # Check if the user is a member of the company
                if not Membership.objects.filter(company=company, user=request.user).exists():
                    return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

                # Filter design efforts based on the retrieved category
                design_efforts = DesignEffort.objects.filter(category=category)

                # Serialize the filtered design efforts
                serializer = DesignEffortSerializer(design_efforts, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Company.DoesNotExist:
                return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)


class RemoveCategoryView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Remove a category",
        responses={200: "Category removed successfully."}
    )
    def delete(self, request, *args, **kwargs):
        category_id = request.data.get('category_id')
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not category_id:
            return Response({'status': 'Category ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            category = Category.objects.get(id=category_id)
            category_company_id = category.company.id

            if str(category_company_id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            category.delete()
            return Response({'status': 'Category removed successfully'}, status=status.HTTP_200_OK)
        except Category.DoesNotExist:
            return Response({'status': 'Category does not exist'}, status=status.HTTP_404_NOT_FOUND)


class DesignEffortListView(generics.ListAPIView):
    serializer_class = DesignEffortSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all design efforts for the current company",
        responses={200: "List of design efforts."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            design_efforts = company.designeffort_set.all()
            serializer = self.get_serializer(design_efforts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)

class CreateDesignEffortView(generics.CreateAPIView):
    serializer_class = DesignEffortSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new design effort",
        responses={201: "Design effort created successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)

            # Ensure the user is an admin of the company
            if not Membership.objects.filter(company=company, user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Save the design effort, passing company as context and category_id
            serializer.save(company=company, category_id=request.data.get('category_id'))

            return Response({'status': 'Design effort created successfully'}, status=status.HTTP_201_CREATED)

        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class UpdateDesignEffortView(generics.UpdateAPIView):
    serializer_class = DesignEffortSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update a design effort",
        responses={200: "Design effort updated successfully."}
    )
    def patch(self, request, *args, **kwargs):
        design_effort_id = request.data.get('effort_id')
        if not design_effort_id:
            return Response({'status': 'Design effort ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            design_effort = DesignEffort.objects.get(id=design_effort_id)

            if str(design_effort.company.id) != str(request.session.get('current_company_id')):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Ensure the user is an admin of the company
            if not Membership.objects.filter(company=design_effort.company, user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            serializer = self.get_serializer(
                design_effort, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'status': 'Design effort updated successfully'}, status=status.HTTP_200_OK)

        except DesignEffort.DoesNotExist:
            return Response({'status': 'Design effort does not exist'}, status=status.HTTP_404_NOT_FOUND)


class DeleteDesignEffortView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete a design effort",
        responses={200: "Design effort deleted successfully."}
    )
    def delete(self, request, *args, **kwargs):
        design_effort_id = request.data.get('effort_id')
        if not design_effort_id:
            return Response({'status': 'Design effort ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if not Membership.objects.filter(company=request.session.get('current_company_id'), user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            design_effort = DesignEffort.objects.get(id=design_effort_id)
            if str(design_effort.company.id) != str(request.session.get('current_company_id')):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            design_effort.delete()
            return Response({'status': 'Design effort deleted successfully'}, status=status.HTTP_200_OK)

        except DesignEffort.DoesNotExist:
            return Response({'status': 'Design effort does not exist'}, status=status.HTTP_404_NOT_FOUND)


class RetrieveSpecificDesignEffortsView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve information on specific design efforts",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'design_effort_ids': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_INTEGER),
                    description='List of design effort IDs'
                )
            },
            required=['design_effort_ids']
        ),
        responses={
            200: "List of design efforts.",
            400: "Bad request.",
            403: "Permission denied.",
            404: "Design effort(s) not found."
        }
    )
    def post(self, request, *args, **kwargs):
        design_effort_ids = request.data.get('design_effort_ids')
        if not design_effort_ids:
            return Response({'status': 'Design effort IDs are required'}, status=status.HTTP_400_BAD_REQUEST)

        design_efforts = DesignEffort.objects.filter(
            id__in=design_effort_ids, company_id=request.session.get('current_company_id'))
        if not design_efforts.exists():
            return Response({'status': 'Design effort(s) not found or do not belong to the current company'}, status=status.HTTP_404_NOT_FOUND)

        serializer = DesignEffortSerializer(design_efforts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CreateMappingView(generics.CreateAPIView):
    serializer_class = MappingSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new mapping",
        responses={201: "Mapping created successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)

            # Ensure the user is an admin of the company
            if not Membership.objects.filter(company=company, user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            mapping = serializer.save(company=company)
            return Response({'status': 'Mapping created successfully', 'id': mapping.id}, status=status.HTTP_201_CREATED)

        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class UpdateMappingView(generics.UpdateAPIView):
    serializer_class = MappingSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update a mapping",
        responses={200: "Mapping updated successfully."}
    )
    def patch(self, request, *args, **kwargs):
        mapping_id = request.data.get('mapping_id')
        if not mapping_id:
            return Response({'status': 'Mapping ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            mapping = Mapping.objects.get(id=mapping_id)
            current_company_id = request.session.get('current_company_id')
            if not current_company_id or str(mapping.company.id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Ensure the user is an admin of the company
            if not Membership.objects.filter(company=mapping.company, user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            serializer = self.get_serializer(
                mapping, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'status': 'Mapping updated successfully'}, status=status.HTTP_200_OK)

        except Mapping.DoesNotExist:
            return Response({'status': 'Mapping does not exist'}, status=status.HTTP_404_NOT_FOUND)


class AddDesignEffortViewMapping(generics.GenericAPIView):
    serializer_class = MappingSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add a design effort to a mapping",
        responses={200: "Design effort added successfully."}
    )
    def post(self, request, *args, **kwargs):
        mapping_id = request.data.get('mapping_id')
        effort_id = request.data.get('effort_id')
        mapping_type = request.data.get('type')
        if not mapping_id or not effort_id or not mapping_type:
            return Response({'status': 'Mapping ID, effort ID, and type are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            mapping = Mapping.objects.get(id=mapping_id)
            effort = DesignEffort.objects.get(id=effort_id)
            current_company_id = request.session.get('current_company_id')
            if not current_company_id or str(mapping.company.id) != str(current_company_id) or str(effort.company.id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Ensure the user is an admin of the company
            if not Membership.objects.filter(company=mapping.company, user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            if mapping.type != mapping_type:
                return Response({'status': 'Mapping type mismatch'}, status=status.HTTP_400_BAD_REQUEST)


            mapping.design_efforts.add(effort)
            return Response({'status': 'Design effort added successfully'}, status=status.HTTP_200_OK)

        except Mapping.DoesNotExist:
            return Response({'status': 'Mapping does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except DesignEffort.DoesNotExist:
            return Response({'status': 'Design effort does not exist'}, status=status.HTTP_404_NOT_FOUND)


class RemoveDesignEffortViewMapping(generics.DestroyAPIView):
    serializer_class = MappingSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Remove a design effort from a mapping",
        responses={200: "Design effort removed successfully."}
    )
    def delete(self, request, *args, **kwargs):
        mapping_id = request.data.get('mapping_id')
        effort_id = request.data.get('effort_id')
        mapping_type = request.data.get('type')
        if not mapping_id or not effort_id or not mapping_type:
            return Response({'status': 'Mapping ID, effort ID, and type are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            mapping = Mapping.objects.get(id=mapping_id)
            effort = DesignEffort.objects.get(id=effort_id)
            current_company_id = request.session.get('current_company_id')
            if not current_company_id or str(mapping.company.id) != str(current_company_id) or str(effort.company.id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Ensure the user is an admin of the company
            if not Membership.objects.filter(company=mapping.company, user=request.user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            if mapping.type != mapping_type:
                return Response({'status': 'Mapping type mismatch'}, status=status.HTTP_400_BAD_REQUEST)

            mapping.design_efforts.remove(effort)
            return Response({'status': 'Design effort removed successfully'}, status=status.HTTP_200_OK)

        except Mapping.DoesNotExist:
            return Response({'status': 'Mapping does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except DesignEffort.DoesNotExist:
            return Response({'status': 'Design effort does not exist'}, status=status.HTTP_404_NOT_FOUND)


class MappingListView(generics.ListAPIView):
    serializer_class = MappingSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all mappings for the current company",
        responses={200: "List of mappings."}
    )
    def post(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user
        mapping_type = request.data.get('type')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        if not mapping_type:
            return Response({'status': 'Mapping type not selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            mappings = company.mapping_set.filter(type=mapping_type)

            serializer = self.serializer_class(mappings, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)


class RemoveMappingView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Remove a mapping",
        responses={200: "Mapping removed successfully."}
    )
    def delete(self, request, *args, **kwargs):
        mapping_id = request.data.get('mapping_id')
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not mapping_id:
            return Response({'status': 'Mapping ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            mapping = Mapping.objects.get(id=mapping_id)
            mapping_company_id = mapping.company.id

            if str(mapping_company_id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            mapping.delete()
            return Response({'status': 'Mapping removed successfully'}, status=status.HTTP_200_OK)
        except Mapping.DoesNotExist:
            return Response({'status': 'Mapping does not exist'}, status=status.HTTP_404_NOT_FOUND)


class CreateProjectView(generics.CreateAPIView):
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Create a new project",
        responses={201: "Project created successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        try:
            company = Company.objects.get(id=current_company_id)
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            project = serializer.save(company=company)
            return Response({'status': 'Project created successfully', 'id': project.id}, status=status.HTTP_201_CREATED)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
class ProjectListView(generics.ListAPIView):
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all projects for the current company",
        responses={200: "List of projects."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            projects = Project.objects.filter(company=company)
            serializer = self.get_serializer(projects, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)

class CreatePurposeView(generics.CreateAPIView):
    serializer_class = PurposeSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Create a new purpose",
        responses={201: "Purpose created successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)
            user = request.user
            if not Membership.objects.filter(company=company, user=user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            # Save the purpose with the associated user and project
            purpose = serializer.save(user=user, project=project)
            
            return Response({'status': 'Purpose created successfully', 'local_id': purpose.local_id}, status=status.HTTP_201_CREATED)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        
class EditPurposeView(generics.UpdateAPIView):
    serializer_class = PurposeSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Edit a purpose",
        responses={200: "Purpose updated successfully."}
    )
    def patch(self, request, *args, **kwargs):
        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        purpose_id = request.data.get('purpose_id')
        if not purpose_id:
            return Response({'status': 'Purpose ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            purpose = Purpose.objects.get(id=purpose_id)
            purpose_company_id = purpose.project.company.id

            if str(purpose_company_id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            serializer = self.get_serializer(purpose, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'status': 'Purpose updated successfully'}, status=status.HTTP_200_OK)
        except Purpose.DoesNotExist:
            return Response({'status': 'Purpose does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
class RemovePurposeView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Remove a purpose",
        responses={200: "Purpose removed successfully."}
    )
    def delete(self, request, *args, **kwargs):
        purpose_id = request.data.get('purpose_id')
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not purpose_id:
            return Response({'status': 'Purpose ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            purpose = Purpose.objects.get(id=purpose_id)
            if purpose.project.company.id != current_company_id:
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)


            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            purpose.delete()
            return Response({'status': 'Purpose removed successfully'}, status=status.HTTP_200_OK)
        except Purpose.DoesNotExist:
            return Response({'status': 'Purpose does not exist'}, status=status.HTTP_404_NOT_FOUND)
        

class PurposeListView(generics.ListAPIView):
    serializer_class = PurposeSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all purposes for a specific project in the current company",
        responses={200: "List of purposes."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = self.kwargs.get('project_id')
        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)

            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Filter purposes based on the specified project
            purposes = Purpose.objects.filter(project=project)
            
            serializer = self.get_serializer(purposes, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        
class CreateProjectEffortView(generics.CreateAPIView):
    queryset = ProjectEffort.objects.all()
    serializer_class = ProjectEffortSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Create a new project effort",
        responses={201: "Project effort created successfully."}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        current_company_id = request.session.get('current_company_id')
        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)
            user = request.user

            # Validate membership
            if not Membership.objects.filter(company=company, user=user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Validate design_effort, outcome, and purpose
            design_effort_id = request.data.get('design_effort')
            outcome_id = request.data.get('outcome')
            purpose_id = request.data.get('purpose')

            design_effort = DesignEffort.objects.get(id=design_effort_id, company=company) if design_effort_id else None
            outcome = Mapping.objects.get(id=outcome_id, company=company) if outcome_id else None
            purpose = Purpose.objects.get(id=purpose_id, project=project)

            # Save the project effort with the associated user and project
            project_effort = serializer.save(user=user, project=project, design_effort=design_effort, outcome=outcome, purpose=purpose)

            return Response({'status': 'Project effort created successfully', 'local_id': project_effort.local_id}, status=status.HTTP_201_CREATED)
        
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        except DesignEffort.DoesNotExist:
            return Response({'status': 'Design effort does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        except Mapping.DoesNotExist:
            return Response({'status': 'Outcome does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        except Purpose.DoesNotExist:
            return Response({'status': 'Purpose does not exist or does not belong to the selected project'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class ListProjectEffortView(generics.ListAPIView):
    serializer_class = ProjectEffortSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all project efforts for a specific project in the current company",
        responses={200: "List of project efforts."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = self.kwargs.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)

            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Filter project efforts based on the specified project
            project_efforts = ProjectEffort.objects.filter(project=project)
            
            serializer = self.get_serializer(project_efforts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        
class EditProjectEffortView(generics.UpdateAPIView):
    serializer_class = ProjectEffortSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Edit a project effort",
        responses={200: "Project effort updated successfully."}
    )
    def patch(self, request, *args, **kwargs):
        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_effort_id = self.kwargs.get('project_effort_id')
        if not project_effort_id:
            return Response({'status': 'Project effort ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            project_effort = ProjectEffort.objects.get(id=project_effort_id)
            project_effort_company_id = project_effort.project.company.id

            if str(project_effort_company_id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            # Validate design_effort, outcome, and purpose if provided in request
            design_effort_id = request.data.get('design_effort')
            outcome_id = request.data.get('outcome')
            purpose_id = request.data.get('purpose')

            if design_effort_id:
                design_effort = DesignEffort.objects.get(id=design_effort_id, company=current_company_id)
                project_effort.design_effort = design_effort
            
            if outcome_id:
                outcome = Mapping.objects.get(id=outcome_id, company=current_company_id)
                project_effort.outcome = outcome
            
            if purpose_id:
                purpose = Purpose.objects.get(id=purpose_id, project=project_effort.project)
                project_effort.purpose = purpose

            project_effort.save()

            serializer = self.get_serializer(project_effort, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response({'status': 'Project effort updated successfully'}, status=status.HTTP_200_OK)
        
        except ProjectEffort.DoesNotExist:
            return Response({'status': 'Project effort does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except DesignEffort.DoesNotExist:
            return Response({'status': 'Design effort does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        except Mapping.DoesNotExist:
            return Response({'status': 'Outcome does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        except Purpose.DoesNotExist:
            return Response({'status': 'Purpose does not exist or does not belong to the selected project'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateValueStatusView(generics.UpdateAPIView):
    serializer_class = ProjectEffortSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Update the value status of a project effort",
        responses={200: "Value status updated successfully."}
    )
    def patch(self, request, *args, **kwargs):
        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_effort_id = self.kwargs.get('project_effort_id')
        if not project_effort_id:
            return Response({'status': 'Project effort ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            project_effort = ProjectEffort.objects.get(id=project_effort_id)
            project_effort_company_id = project_effort.project.company.id

            if str(project_effort_company_id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            serializer = self.get_serializer(
                project_effort, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'status': 'Value status updated successfully'}, status=status.HTTP_200_OK)
        except ProjectEffort.DoesNotExist:
            return Response({'status': 'Project effort does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateCheckedByEffortView(generics.UpdateAPIView):
    serializer_class = ProjectEffortSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Update the checked by status of a project effort",
        responses={200: "Checked by status updated successfully."}
    )
    def patch(self, request, *args, **kwargs):
        user = request.user
        current_company_id = request.session.get('current_company_id')

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_effort_id = self.kwargs.get('project_effort_id')
        if not project_effort_id:
            return Response({'status': 'Project effort ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            project_effort = ProjectEffort.objects.get(id=project_effort_id)
            project_effort_company_id = project_effort.project.company.id

            if str(project_effort_company_id) != str(current_company_id):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            checked_by_id = request.data.get('checked_by')
            if checked_by_id is None:
                return Response({'status': 'Checked by ID is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Verify if the checked_by user exists in the company
            if not Membership.objects.filter(company_id=current_company_id, user_id=checked_by_id).exists():
                return Response({'status': 'Checked by user does not exist in the company'}, status=status.HTTP_404_NOT_FOUND)

            # Assign checked_at timestamp if checked_by is being updated
            if 'checked_by' in request.data:
                request.data['checked_at'] = timezone.now()

            serializer = self.get_serializer(
                project_effort, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'status': 'Checked by status updated successfully'}, status=status.HTTP_200_OK)
        except ProjectEffort.DoesNotExist:
            return Response({'status': 'Project effort does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DestroyProjectEffortView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Delete a project effort",
        responses={200: "Project effort deleted successfully."}
    )
    def delete(self, request, *args, **kwargs):
        project_effort_id = self.kwargs.get('project_effort_id')
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not project_effort_id:
            return Response({'status': 'Project effort ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            project_effort = ProjectEffort.objects.get(id=project_effort_id)
            if project_effort.project.company.id != current_company_id:
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            # Additional membership check
            if not Membership.objects.filter(company_id=current_company_id, user=user, is_admin=True):
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            project_effort.delete()
            return Response({'status': 'Project effort deleted successfully'}, status=status.HTTP_200_OK)
        
        except ProjectEffort.DoesNotExist:
            return Response({'status': 'Project effort does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Insights Views

class InsightsValueRatioView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the value ratios of project efforts",
        responses={200: "List of values of project efforts."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = self.kwargs.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)

            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Filter project efforts based on the specified project and realized status
            project_efforts = ProjectEffort.objects.filter(project=project, value_status='REA')

            if start_date and end_date:
                try:
                    start_date = datetime.strptime(start_date, '%Y-%m-%d')
                    end_date = datetime.strptime(end_date, '%Y-%m-%d')
                    project_efforts = project_efforts.filter(checked_at__gte=start_date, checked_at__lte=end_date)
                except ValueError:
                    return Response({'status': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)


            # Fetch design efforts associated with project efforts
            design_efforts = DesignEffort.objects.filter(id__in=project_efforts.values_list('design_effort_id', flat=True))

            # Initialize dictionary to hold value counts
            value_counts = {value.name: 0 for value in Mapping.objects.filter(company=company, type='VAL')}

            # Count values based on design efforts' associations with Mapping objects
            for design_effort in design_efforts:
                for value in Mapping.objects.filter(design_efforts=design_effort, type='VAL'):
                    if value.title in value_counts:
                        value_counts[value.title] += 1

            # Calculate value ratios based on total realized efforts
            total_realized_efforts = project_efforts.count()
            value_ratios = []

            for value_title, count in value_counts.items():
                if total_realized_efforts > 0:
                    ratio = (count / total_realized_efforts) * 100
                else:
                    ratio = 0
                value_ratios.append({
                    'value': value_title,
                    'ratio': ratio
                })

            return Response(value_ratios, status=status.HTTP_200_OK)

        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)


class InsightsObjectiveRatioView(generics.ListAPIView):
    authentication_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the objective ratios of project efforts",
        responses={200: "List of objectives of project efforts."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = self.kwargs.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)

            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Filter project efforts based on the specified project and realized status
            project_efforts = ProjectEffort.objects.filter(project=project, value_status='REA')

            if start_date and end_date:
                try:
                    start_date = datetime.strptime(start_date, '%Y-%m-%d')
                    end_date = datetime.strptime(end_date, '%Y-%m-%d')
                    project_efforts = project_efforts.filter(checked_at__gte=start_date, checked_at__lte=end_date)
                except ValueError:
                    return Response({'status': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)

            # Fetch design efforts associated with project efforts
            design_efforts = DesignEffort.objects.filter(id__in=project_efforts.values_list('design_effort_id', flat=True))

            # Initialize dictionary to hold objective counts
            objective_counts = {objective.name: 0 for objective in Mapping.objects.filter(company=company, type='OBJ')}

            # Count objectives based on design efforts' associations with Mapping objects
            for design_effort in design_efforts:
                for objective in Mapping.objects.filter(design_efforts=design_effort, type='OBJ'):
                    if objective.title in objective_counts:
                        objective_counts[objective.title] += 1

            # Calculate objective ratios based on total realized efforts
            total_realized_efforts = project_efforts.count()
            objective_ratios = []

            for objective_title, count in objective_counts.items():
                if total_realized_efforts > 0:
                    ratio = (count / total_realized_efforts) * 100
                else:
                    ratio = 0
                objective_ratios.append({
                    'objective': objective_title,
                    'ratio': ratio
                })

            return Response(objective_ratios, status=status.HTTP_200_OK)

        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)
        
class InsightsEffortByCategoryCountView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the count of realized project efforts by category",
        responses={200: "List of counts of realized project efforts by category."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = self.kwargs.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)

            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Filter project efforts based on the specified project and realized status
            project_efforts = ProjectEffort.objects.filter(project=project, value_status='REA')

            if start_date and end_date:
                try:
                    start_date = datetime.strptime(start_date, '%Y-%m-%d')
                    end_date = datetime.strptime(end_date, '%Y-%m-%d')
                    project_efforts = project_efforts.filter(checked_at__gte=start_date, checked_at__lte=end_date)
                except ValueError:
                    return Response({'status': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)

            # Fetch design efforts associated with project efforts
            design_efforts = DesignEffort.objects.filter(id__in=project_efforts.values_list('design_effort_id', flat=True))

            # Initialize dictionary to hold category counts
            category_counts = {category.name: 0 for category in Category.objects.filter(company=company)}

            # Count design efforts based on their categories
            for design_effort in design_efforts:
                if design_effort.category.name in category_counts:
                    category_counts[design_effort.category.name] += 1

            return Response(category_counts, status=status.HTTP_200_OK)

        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class InsightsLatestValuesView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the latest values of project efforts checked",
        responses={200: "List of latest values of project efforts."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = self.kwargs.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)

            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            # Filter project efforts based on the specified project and value status
            project_efforts = ProjectEffort.objects.filter(project=project).exclude(value_status='YBC')

            if start_date and end_date:
                try:
                    start_date = datetime.strptime(start_date, '%Y-%m-%d')
                    end_date = datetime.strptime(end_date, '%Y-%m-%d')
                    project_efforts = project_efforts.filter(checked_at__gte=start_date, checked_at__lte=end_date)
                except ValueError:
                    return Response({'status': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)
            
            project_efforts = project_efforts.order_by('-checked_at')[:5]

            # Fetch design efforts associated with project efforts
            design_efforts = DesignEffort.objects.filter(id__in=project_efforts.values_list('design_effort_id', flat=True))

            # Initialize dictionary to hold latest values
            latest_values = {}

            # Serialize project efforts
            project_efforts_data = ProjectEffortSerializer(project_efforts, many=True).data

            # Get the latest value of each project effort
            for project_effort_data in project_efforts_data:
                project_effort_id = project_effort_data['id']
                project_effort = project_efforts.get(id=project_effort_id)
                design_effort = design_efforts.get(id=project_effort.design_effort_id)
                values = Mapping.objects.filter(design_efforts=design_effort, type='VAL')
                values_data = [value.title for value in values]
                latest_values[project_effort_id] = {
                    'project_effort': project_effort_data,
                    'values': values_data
                }
            
            return Response(latest_values, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class InsightsLatestObjectivesView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the latest objectives of project efforts checked",
        responses={200: "List of latest objectives of project efforts."}
    )
    def get(self, request, *args, **kwargs):
        current_company_id = request.session.get('current_company_id')
        user = request.user

        if not current_company_id:
            return Response({'status': 'No company selected'}, status=status.HTTP_400_BAD_REQUEST)

        project_id = self.kwargs.get('project_id')
        if not project_id:
            return Response({'status': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        try:
            company = Company.objects.get(id=current_company_id)
            project = Project.objects.get(id=project_id, company=company)

            # Check if the user is a member of the company
            if not Membership.objects.filter(company=company, user=user).exists():
                return Response({'status': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            # Filter project efforts based on the specified project and value status
            project_efforts = ProjectEffort.objects.filter(project=project).exclude(value_status='YBC')

            if start_date and end_date:
                try:
                    start_date = datetime.strptime(start_date, '%Y-%m-%d')
                    end_date = datetime.strptime(end_date, '%Y-%m-%d')
                    project_efforts = project_efforts.filter(checked_at__gte=start_date, checked_at__lte=end_date)
                except ValueError:
                    return Response({'status': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)
            
            project_efforts = project_efforts.order_by('-checked_at')[:5]

            # Fetch design efforts associated with project efforts
            design_efforts = DesignEffort.objects.filter(id__in=project_efforts.values_list('design_effort_id', flat=True))

            # Initialize dictionary to hold latest objectives
            latest_objectives = {}

            # Serialize project efforts
            project_efforts_data = ProjectEffortSerializer(project_efforts, many=True).data

            # Get the latest objectives of each project effort
            for project_effort_data in project_efforts_data:
                project_effort_id = project_effort_data['id']
                project_effort = project_efforts.get(id=project_effort_id)
                design_effort = design_efforts.get(id=project_effort.design_effort_id)
                objectives = Mapping.objects.filter(design_efforts=design_effort, type='OBJ')
                objectives_data = [objective.title for objective in objectives]
                latest_objectives[project_effort_id] = {
                    'project_effort': project_effort_data,
                    'objectives': objectives_data
                }
            
            return Response(latest_objectives, status=status.HTTP_200_OK)
        except Company.DoesNotExist:
            return Response({'status': 'Company does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        except Project.DoesNotExist:
            return Response({'status': 'Project does not exist or does not belong to the selected company'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'status': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

