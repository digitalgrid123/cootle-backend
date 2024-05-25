# urls.py
from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from portal.views import UserRegistrationView, UserVerificationView, UserLoginView, UserLoginVerificationView, UserUpdateView, CreateCompanyView, InviteUserView, AcceptInvitationView
from rest_framework_simplejwt.views import (
      TokenObtainPairView,
      TokenRefreshView,
)

schema_view = get_schema_view(
   openapi.Info(
      title="Cootle APIs",
      default_version='v1',
      description="API documentation for Cootle",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@yourapi.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
   path('api/user/register/', UserRegistrationView.as_view(), name='user-registration'),
   path('api/user/verify/', UserVerificationView.as_view(), name='user-verification'),
   path('api/user/login/', UserLoginView.as_view(), name='user-login'),
   path('api/user/login/verify/', UserLoginVerificationView.as_view(), name='user-login-verification'),
   path('api/user/update/', UserUpdateView.as_view(), name='user-update'),
   path('api/company/create/', CreateCompanyView.as_view(), name='create-company'),
   path('api/invite/', InviteUserView.as_view(), name='invite-user'),
   path('api/accept/', AcceptInvitationView.as_view(), name='accept-invitation'),
       # ... your other urls
   path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
   path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
   re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
   path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
