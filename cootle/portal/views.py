from django.shortcuts import render
from rest_framework import status, generics
from rest_framework.response import Response
from .models import User
from .serializers import UserRegistrationSerializer, UserVerificationSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .utils import send_verification_email

# Create your views here.

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer

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
            return Response({'status': 'User verified'}, status=status.HTTP_200_OK)
        else:
            return Response({'status': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)
        
