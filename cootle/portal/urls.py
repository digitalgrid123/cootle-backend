# urls.py
from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from portal.views import csrf_token, DefaultMappingsView, ResetMappingDataView,  DashboardInfoView, UserRegistrationView, UserVerificationView, UserLoginView, UserLoginVerificationView, UserUpdateView, UserInfoView, CreateCompanyView, SetCurrentCompanyView, EditCompanyView, CompanyListView, InviteUserView, AcceptEmailInvitationView, AcceptInvitationView, RejectInvitationView, InvitationListView, ListInvitationsView, RemoveMemberView, NotificationListView, MarkReadNotifications, RemoveNotificationView, RemoveAllNotificationsView, CreateCategoryView, CategoryListView, CategoryDetailView, RemoveCategoryView, DesignEffortListView, CreateDesignEffortView, UpdateDesignEffortView, DeleteDesignEffortView, CreateMappingView, UpdateMappingView, AddDesignEffortViewMapping, RemoveDesignEffortViewMapping, MappingListView, RetrieveSpecificDesignEffortsView, RemoveMappingView, CreateProjectView, ProjectListView, CreatePurposeView, PurposeListView, EditPurposeView, RemovePurposeView
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
   path('api/csrf-token/', csrf_token, name='csrf-token'),
   path('api/default-mappings/', DefaultMappingsView.as_view(), name='default-mappings'),
   path('api/reset-mapping-data/', ResetMappingDataView.as_view(), name='reset-mapping-data'),
   path('api/dashboard/', DashboardInfoView.as_view(), name='dashboard-info'),
   path('api/user/register/', UserRegistrationView.as_view(), name='user-registration'),
   path('api/user/verify/', UserVerificationView.as_view(), name='user-verification'),
   path('api/user/login/', UserLoginView.as_view(), name='user-login'),
   path('api/user/login/verify/', UserLoginVerificationView.as_view(), name='user-login-verification'),
   # path('api/user/logout/', UserLogoutView.as_view(), name='user-logout'),
   path('api/user/update/', UserUpdateView.as_view(), name='user-update'),
   path('api/user/info/', UserInfoView.as_view(), name='user-info'),
   path('api/company/create/', CreateCompanyView.as_view(), name='create-company'),
   path('api/company/set/', SetCurrentCompanyView.as_view(), name='set-current-company'),
   path('api/company/edit/', EditCompanyView.as_view(), name='edit-company'),
   path('api/company/list/', CompanyListView.as_view(), name='company-list'),
   path('api/invite/', InviteUserView.as_view(), name='invite-user'),
   path('api/accept/', AcceptEmailInvitationView.as_view(), name='accept-email-invitation'),
   path('api/invite/accept/', AcceptInvitationView.as_view(), name='accept-invitation'),
   path('api/invite/reject/', RejectInvitationView.as_view(), name='reject-invitation'),
   path('api/invitations/', InvitationListView.as_view(), name='invitations-list'),
   path('api/invitations/list/', ListInvitationsView.as_view(), name='list-invitations'),
   # path('api/members/', CompanyMembersView.as_view(), name='company-members'),
   path('api/members/remove/', RemoveMemberView.as_view(), name='remove-member'),
   path('api/notifications/', NotificationListView.as_view(), name='notifications-list'),
   path('api/notifications/mark-read/', MarkReadNotifications.as_view(), name='mark-read-notifications'),
   path('api/notifications/remove/', RemoveNotificationView.as_view(), name='remove-notification'),
   path('api/notifications/remove-all/', RemoveAllNotificationsView.as_view(), name='remove-all-notifications'),
   path('api/category/create/', CreateCategoryView.as_view(), name='create-category'),
   path('api/categories/', CategoryListView.as_view(), name='categories-list'),
   path('api/categories/<int:category_id>/design-efforts/', CategoryDetailView.as_view(), name='category-detail'),
   path('api/category/remove/', RemoveCategoryView.as_view(), name='remove-category'),
   path('api/design-efforts/', DesignEffortListView.as_view(), name='design-efforts-list'),
   path('api/design-effort/create/', CreateDesignEffortView.as_view(), name='create-design-effort'),
   path('api/design-effort/update/', UpdateDesignEffortView.as_view(), name='update-design-effort'),
   path('api/design-effort/delete/', DeleteDesignEffortView.as_view(), name='delete-design-effort'),
   path('api/mapping/create/', CreateMappingView.as_view(), name='create-mapping'),
   path('api/mapping/update/', UpdateMappingView.as_view(), name='update-mapping'),
   path('api/mapping/list/', MappingListView.as_view(), name='mapping-list'),
   path('api/mapping/design-effort/add/', AddDesignEffortViewMapping.as_view(), name='add-design-effort'),
   path('api/mapping/design-effort/remove/', RemoveDesignEffortViewMapping.as_view(), name='remove-design-effort'),
   path('api/design-effort/retrieve/', RetrieveSpecificDesignEffortsView.as_view(), name='retrieve-specific-design-efforts'),
   path('api/mapping/remove/', RemoveMappingView.as_view(), name='remove-mapping'),
   path('api/project/create/', CreateProjectView.as_view(), name='create-project'),
   path('api/projects/', ProjectListView.as_view(), name='projects-list'),
   path('api/purpose/create/', CreatePurposeView.as_view(), name='create-purpose'),
   path('api/projects/<int:project_id>/purposes/', PurposeListView.as_view(), name='purpose-list'),
   path('api/purpose/edit/', EditPurposeView.as_view(), name='edit-purpose'),
   path('api/purpose/remove/', RemovePurposeView.as_view(), name='remove-purpose'),
       # ... your other urls
   path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
   path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
   re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
   path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
