from django.urls import path
from .views import UserView, RoleView, PermissionView
from .auth_views import RegisterView, LoginView, RefreshTokenView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("refresh-token/", RefreshTokenView.as_view(), name="refresh-token"),
    path("users/", UserView.as_view(), name="users"),
    path("users/<int:user_id>/", UserView.as_view(), name="user-detail"),
    path("roles/", RoleView.as_view(), name="roles"),
    path("roles/<int:role_id>/", RoleView.as_view(), name="role-detail"),
    path("permissions/", PermissionView.as_view(), name="permissions"),
    path(
        "permissions/<int:permission_id>/",
        PermissionView.as_view(),
        name="permission-detail",
    ),
]
