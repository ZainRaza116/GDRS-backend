from django.urls import path
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

app_name = 'Authentication'

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/',LoginView.as_view(), name="login" ),
    path('change_password/',ChangePasswordView.as_view(), name="change_password"),
    path('email_verify/', VerifyEmailView.as_view(), name="email_verify")
]