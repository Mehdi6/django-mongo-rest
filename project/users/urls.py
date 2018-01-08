from django.conf.urls import url

from .views import *

urlpatterns = [
    #Does not require quthentication
    url(r'^login/$', LoginView.as_view(), name=r"login"),
    url(r'^registration/$', SignUpView.as_view(), name=r"signup"),
    url(r'^registration/verify-email/$', ValidateEmailView.as_view(), name=r"verify_email"),
    url(r'^password/reset/$', ResetPasswordView.as_view(), name=r"pwd_reset"),
    url(r'^password/reset/confirm/$', ConfirmPasswordView.as_view(), name=r"pwd_confirm"),
    
    # require authentication
    url(r'^logout/$', LogoutView.as_view(), name=r"logout"),
    url(r'^password/change/$', PasswordChangeView.as_view(), name=r"pwd_change"),
    url(r'^user/$', UserView.as_view(), name=r"user_profile"),
    
]
