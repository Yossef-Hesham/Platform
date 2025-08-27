# urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

# app_name = 'account'

urlpatterns = [
    # Authentication endpoints
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('delete-account/', views.delete_account, name='delete_account'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Profile endpoints
    path('profile/', views.UserProfileView.as_view(), name='user_profile'),
    path('profile/teacher/', views.TeacherProfileView.as_view(), name='teacher_profile'),
    path('profile/student/', views.StudentProfileView.as_view(), name='student_profile'),
    path('profile/parent/', views.ParentProfileView.as_view(), name='parent_profile'),
    
    # Email verification
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('resend-verification-email/', views.resend_verification_email, name='resend_verification_email'),

    # Password management
    path('change-password/', views.change_password, name='change_password'),
    path('password-reset/request/', views.password_reset_request, name='password_reset_request'),
    path('password-reset/confirm/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),
    
    # Admin functions
    path('approve-teacher/<int:teacher_id>/', views.approve_teacher, name='approve_teacher'),
    
    # Parent-child linking
    path('link-child/', views.link_child_to_parent, name='link_child'),
]