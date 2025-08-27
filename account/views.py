# views.py
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import login, logout
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import uuid
import random


from .models import (
    User, TeacherProfile, StudentProfile, ParentProfile,
    EmailVerification, PasswordResetToken
)
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,
    TeacherProfileSerializer, StudentProfileSerializer, ParentProfileSerializer,
    PasswordChangeSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)



class RegisterView(APIView):
    """
    User registration endpoint
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        print("POST /register called with data:", request.data)
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            print('User registration successful')
            user = serializer.save()
            
            # Generate email verification token
            self._send_verification_email(user)
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            token_to_verify = EmailVerification.objects.get(user=user).token

            return Response({
                'message': 'Registration successful. Please check your email to verify your account.',
                'user': UserProfileSerializer(user).data,
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'token_to_verify': token_to_verify
                }
            }, status=status.HTTP_201_CREATED)
        
        else:
            print(serializer.errors) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    def _send_verification_email(self, user):
        """Send email verification"""
        print("isssss seeeeeenntnnnnnnt")
        
        token = str(random.randint(1000, 9999))
        expires_at = timezone.now() + timedelta(hours=24)

        # Save token to DB
        EmailVerification.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )

        # Build verification link
        # verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}"

        try:
            send_mail(
                subject='Verify Your Email - Courses Platform',
                message=f'Please click the following link to verify your email:\n\n{token}',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )
            return True  # success
        except Exception as e:
            # Log the error (so you see it in server logs)
            print(f"[ERROR] Failed to send verification email: {e}")
            return False  # failure


from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions
from datetime import timedelta
import random
import logging

# Add these imports - adjust based on your project structure
from django.contrib.auth.models import User  # or your custom user model
from .models import EmailVerification  # adjust the import path as needed

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def resend_verification_email(request, email):
    """
    Send email verification token to user
    
    Args:
        request: HTTP request object
        email: User email address from URL parameter
        
    Returns:
        JsonResponse: Success/failure status with appropriate message
    """
    try:
        # Get user or return 404 if not found
        user = get_object_or_404(User, email=email)
        
        # Delete any existing verification tokens for this user
        EmailVerification.objects.filter(user=user).delete()
        
        # Generate new verification token
        token = str(random.randint(1000, 9999))
        expires_at = timezone.now() + timedelta(hours=24)
        
        # Create new verification token
        EmailVerification.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )
        
        # Send verification email
        send_mail(
            subject='Verify Your Email - Courses Platform',
            message=f'Your verification code is: {token}\n\n'
                   f'This code will expire in 24 hours.\n\n'
                   f'If you did not request this verification, please ignore this email.',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            fail_silently=False,
        )
        
        logger.info(f"Verification email sent successfully to {email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Verification email sent successfully',
            'token': token  # You can remove this in production for security
        })
        
    except User.DoesNotExist:
        logger.warning(f"Attempt to send verification email to non-existent user: {email}")
        return JsonResponse({
            'success': False,
            'error': 'User not found'
        }, status=404)
        
    except Exception as e:
        logger.error(f"Failed to send verification email to {email}: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to send verification email'
        }, status=500)


from rest_framework.parsers import JSONParser

class LoginView(APIView):
    """
    User login endpoint
    """
    permission_classes = [permissions.AllowAny]
    parser_classes = [JSONParser]
    

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            if user.email_verified is False:
                return Response({
                    'error': 'Email not verified. Please check your email for the verification link.'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            return Response({
                'message': 'Login successful',
                'user': UserProfileSerializer(user).data,
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            }, status=status.HTTP_200_OK)
        
        
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class LogoutView(APIView):
    """
    User logout endpoint
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            return Response({
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                'error': 'Invalid token'
            }, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(RetrieveUpdateAPIView):
    """
    Get and update user profile
    """
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user


class TeacherProfileView(RetrieveUpdateAPIView):
    """
    Get and update teacher profile
    """
    serializer_class = TeacherProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        user = self.request.user
        if not user.is_teacher:
            raise permissions.PermissionDenied("Only teachers can access this endpoint")
        
        profile, created = TeacherProfile.objects.get_or_create(user=user)
        return profile


class StudentProfileView(RetrieveUpdateAPIView):
    """
    Get and update student profile
    """
    serializer_class = StudentProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        user = self.request.user
        if not user.is_student:
            raise permissions.PermissionDenied("Only students can access this endpoint")
        
        profile, created = StudentProfile.objects.get_or_create(user=user)
        return profile


class ParentProfileView(RetrieveUpdateAPIView):
    """""
    Get and update parent profile
    """
    serializer_class = ParentProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        user = self.request.user
        if not user.is_parent:
            raise permissions.PermissionDenied("Only parents can access this endpoint")
        
        profile, created = ParentProfile.objects.get_or_create(user=user)
        return profile


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_email(request, token):
    """
    Email verification endpoint
    """
    try:
        verification = EmailVerification.objects.get(
            token=token,
            is_used=False
        )
        
        if verification.is_expired:
            return Response({
                'error': 'Verification token has expired'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify the email
        user = verification.user
        user.email_verified = True
        user.save(update_fields=['email_verified'])
        
        # Mark token as used
        verification.is_used = True 
        verification.save(update_fields=['is_used'])
        
        return Response({
            'message': 'Email verified successfully'
        }, status=status.HTTP_200_OK)
    
    except EmailVerification.DoesNotExist:
        return Response({
            'error': 'Invalid verification token'
        }, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def change_password(request):
    """
    Password change endpoint
    """
    serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        return Response({
            'message': 'Password changed successfully'
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

import logging
logger = logging.getLogger(__name__)

from account.models import User 
from django.conf import settings
import logging


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def password_reset_request(request):
    try:
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=404)

            # Generate reset token
            token = str(random.randint(1000, 9999))
            expires_at = timezone.now() + timedelta(hours=1)
            
            logger.info(f"Creating token for user {user.id}")
            
            # Create reset token
            reset_token = PasswordResetToken.objects.create(
                user=user,
                token=token,
                expires_at=expires_at
            )
            
            logger.info(f"Token created: {reset_token.id}")
            
            # Send reset email
            subject = 'Password Reset Request - Courses Platform'
            message = f'''
            Hello {user.username}, Your password reset code is: {token} '''
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [user.email]
            
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False,
            )
            
            logger.info(f"Password reset email sent to {user.email}")
            
            return Response({
                'message': 'Password reset email sent successfully'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return Response({'error': 'Internal server error. Please try again later.'}, status=500)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def password_reset_confirm(request, token):
    """
    Password reset confirmation endpoint
    """
    try:
        reset_token = PasswordResetToken.objects.get(
            token=token,
            is_used=False
        )
        
        if reset_token.is_expired:
            return Response({
                'error': 'Reset token has expired'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = PasswordResetConfirmSerializer(data=request.data)
        
        if serializer.is_valid():
            # Reset the password
            user = reset_token.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Mark token as used
            reset_token.is_used = True
            reset_token.save(update_fields=['is_used'])
            
            return Response({
                'message': 'Password reset successfully'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    except PasswordResetToken.DoesNotExist:
        return Response({
            'error': 'Invalid reset token'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def link_child_to_parent(request):
    """
    Endpoint for parents to link children to their account
    """
    if not request.user.is_parent:
        return Response({
            'error': 'Only parents can link children'
        }, status=status.HTTP_403_FORBIDDEN)
    
    child_username = request.data.get('child_username')
    
    try:
        child = User.objects.get(username=child_username, user_type='student')
        
        if child.parent:
            return Response({
                'error': 'This student is already linked to a parent'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        child.parent = request.user
        child.save(update_fields=['parent'])
        
        return Response({
            'message': f'Successfully linked {child.full_name} to your account'
        }, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({
            'error': 'Student not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def approve_teacher(request, teacher_id):
    """
    Endpoint for admins to approve teachers
    """
    if not request.user.is_admin:
        return Response({
            'error': 'Only admins can approve teachers'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        teacher_profile = TeacherProfile.objects.get(user__id=teacher_id)
        teacher_profile.approve(request.user)
        
        return Response({
            'message': f'Teacher {teacher_profile.user.full_name} approved successfully'
        }, status=status.HTTP_200_OK)
    
    except TeacherProfile.DoesNotExist:
        return Response({
            'error': 'Teacher not found'
        }, status=status.HTTP_404_NOT_FOUND)


from django.contrib.auth.decorators import login_required

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        logout(request)
        user.delete()
        return Response({
            'message': 'Account deleted successfully'
        }, status=status.HTTP_204_NO_CONTENT)

    return Response({
        'error': 'Invalid request method'
    }, status=status.HTTP_405_METHOD_NOT_ALLOWED)
