from django.shortcuts import render
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.db import transaction
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from .permissions import IsAdminUser
from .models import User, Company, Invitation, Membership
from .serializers import UserSerializer, UserAccessSerializer, UserVerificationSerializer, UserUpdateSerializer, CompanySerializer, InvitationSerializer, AcceptEmailInvitationSerializer, AcceptInvitationSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .utils import send_verification_email, send_login_email, send_invitation_email
from .admin import assign_company

# Create your views here.

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
    serializer_class =  UserVerificationSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify a user with email and verification code",
        responses={
            200: "Email verified successfully.",
            400: "Invalid verification code."
        },
        manual_parameters=[
            openapi.Parameter('email', openapi.IN_QUERY, description="Email of the user", type=openapi.TYPE_STRING),
            openapi.Parameter('verification_code', openapi.IN_QUERY, description="Verification code sent to the email", type=openapi.TYPE_STRING),
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
            openapi.Parameter('email', openapi.IN_QUERY, description="Email of the user", type=openapi.TYPE_STRING),
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
    serializer_class =  UserVerificationSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify a user with email and login code",
        responses={
            200: "User logged in successfully.",
            400: "Invalid login code."
        },
        manual_parameters=[
            openapi.Parameter('email', openapi.IN_QUERY, description="Email of the user", type=openapi.TYPE_STRING),
            openapi.Parameter('verification_code', openapi.IN_QUERY, description="Login code sent to the email", type=openapi.TYPE_STRING),
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
        
class UserLogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout the user",
        responses={200: "User logged out successfully."}
    )
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({'status': 'User logged out successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': 'Error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
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
        user = request.user
        company = Company.objects.filter(membership__user=user).first()
        if company:
            company_serializer = CompanySerializer(company)
            return Response({'status': 'Dashboard info', 'user': user.fullname, 'email': user.email, 'company': company_serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({'status': 'Dashboard info', 'user': user.fullname, 'email': user.email}, status=status.HTTP_200_OK)

class InviteUserView(generics.CreateAPIView):
    serializer_class = InvitationSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Invite a new user to a company",
        responses={201: "Invitation sent successfully."}
    )
    def post(self, request, *args, **kwargs):
        user = request.user
        try:
            company = user.membership_set.get(is_admin=True).company
        except Membership.DoesNotExist:
            raise ValidationError('User is not associated with any company.')


        request.data['company'] = company.pk
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        invitation = serializer.save(invited_by=user)
        invitation.token = get_random_string(length=32)
        invitation.save()
        send_invitation_email(invitation)
        return Response({'status': 'Invitation sent successfully'}, status=status.HTTP_201_CREATED)

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
        email = serializer.validated_data['email']

        try:
            invitation = Invitation.objects.get(token=token, email=email, accepted=False)
        except Invitation.DoesNotExist:
            raise ValidationError('Invalid or expired token.')

        user, created = User.objects.get_or_create(email=email)
        if created:
            user.is_verified = True
            user.save()
        elif not user.is_verified:
            raise ValidationError('User already exists but is not verified.')

        with transaction.atomic():
            invitation.accepted = True
            invitation.accepted_at = timezone.now()
            invitation.save()
            assign_company(user, invitation.company, is_admin=False)

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
        email = serializer.validated_data['email']
        company = serializer.validated_data['company']

        try:
            invitation = Invitation.objects.get(email=email, company=company, accepted=False)
        except Invitation.DoesNotExist:
            raise ValidationError('Invalid or expired invitation.')

        user = request.user
        with transaction.atomic():
            invitation.accepted = True
            invitation.accepted_at = timezone.now()
            invitation.save()
            assign_company(user, company, is_admin=False)

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
        email = serializer.validated_data['email']
        company = serializer.validated_data['company']

        try:
            invitation = Invitation.objects.get(email=email, company=company, accepted=False)
        except Invitation.DoesNotExist:
            raise ValidationError('Invalid or expired invitation.')

        invitation.rejected = True
        invitation.save()
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
        invitations = Invitation.objects.filter(email=user.email)
        serializer = self.get_serializer(invitations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


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
        return Response({'status': 'Company created successfully'}, status=status.HTTP_201_CREATED)
    
    
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