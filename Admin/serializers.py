# serializers.py
from rest_framework import serializers
from account.models import User
from teacher.models import Course

class UserSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 
            'user_type', 'phone_number', 'date_joined', 'last_login',
            'is_active', 'email_verified', 'parent', 'password', 'confirm_password'
        ]
        read_only_fields = ['date_joined', 'last_login']
        extra_kwargs = {
            'email': {'required': True},
            'user_type': {'required': True},
            'email_verified': {'required': True}
        }

class CourseSerializer(serializers.ModelSerializer):
    teacher_name = serializers.CharField(source='teacher.full_name', read_only=True)
    
    class Meta:
        model = Course
        fields = [
            'id', 'title', 'description', 'teacher', 'teacher_name',
            'status', 'difficulty', 'price', 'duration_hours',
            'total_sections', 'total_quizzes', 'total_enrollments',
            'created_at', 'updated_at'
        ]