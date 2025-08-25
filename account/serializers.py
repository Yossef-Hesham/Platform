# serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, TeacherProfile, StudentProfile, ParentProfile


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)

    parent = serializers.SlugRelatedField(
        queryset=User.objects.filter(user_type='parent'),
        slug_field='username', allow_null=True, required=False
    )

    class Meta:
        model = User
        fields = (
            'username', 'email', 'password', 'password_confirm',
            'first_name', 'last_name', 'user_type', 'phone_number',
            'date_of_birth', 'bio', 'address', 'city', 'country', 'profile_picture',
            'parent',
        )
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'phone_number': {'required': True},
            'user_type': {'required': True},
            'date_of_birth': {'required': True},
        }
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        
        # Create profile based on user type
        if user.user_type == 'teacher':
            TeacherProfile.objects.create(user=user)
        elif user.user_type == 'student':
            StudentProfile.objects.create(user=user)
        elif user.user_type == 'parent':
            ParentProfile.objects.create(user=user)
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    username_or_email = serializers.CharField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        username_or_email = attrs.get('username_or_email')
        password = attrs.get('password')
        
        if username_or_email and password:
            # Try to authenticate with username first
            user = authenticate(username=username_or_email, password=password)
            
            # If that fails, try with email
            if not user:
                try:
                    user_obj = User.objects.get(email=username_or_email)
                    user = authenticate(username=user_obj.username, password=password)
                except User.DoesNotExist:
                    pass
            
            if not user:
                raise serializers.ValidationError('Invalid credentials')
            
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled')
            
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include username/email and password')


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile information
    """
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name',
            'full_name', 'user_type', 'phone_number', 'profile_picture',
            'date_of_birth', 'bio', 'address', 'city', 'country',
            'email_verified', 'date_joined', 'last_login'
        )
        read_only_fields = ('id', 'username', 'user_type', 'email_verified', 'date_joined', 'last_login')


class TeacherProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for teacher profile
    """
    user = UserProfileSerializer(read_only=True)
    
    class Meta:
        model = TeacherProfile
        fields = '__all__'
        read_only_fields = ('is_approved', 'approved_by', 'approved_at')


class StudentProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for student profile
    """
    user = UserProfileSerializer(read_only=True)
    parent_info = serializers.SerializerMethodField()
    
    class Meta:
        model = StudentProfile
        fields = '__all__'
    
    def get_parent_info(self, obj):
        if obj.user.parent:
            return {
                'id': obj.user.parent.id,
                'name': obj.user.parent.full_name,
                'email': obj.user.parent.email,
                'phone': obj.user.parent.phone_number
            }
        return None


class ParentProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for parent profile
    """
    user = UserProfileSerializer(read_only=True)
    children = serializers.SerializerMethodField()
    
    class Meta:
        model = ParentProfile
        fields = '__all__'
    
    def get_children(self, obj):
        children = obj.get_children()
        return [
            {
                'id': child.id,
                'name': child.full_name,
                'username': child.username,
                'grade_level': getattr(child.student_profile, 'grade_level', None) if hasattr(child, 'student_profile') else None
            }
            for child in children
        ]


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change
    """
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        return attrs
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect")
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request
    """
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("No user found with this email address")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation
    """
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs