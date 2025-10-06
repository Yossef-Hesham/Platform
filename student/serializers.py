from rest_framework import serializers
from .models import StudentProgress, StudentCertificate, StudentNote
from teacher.models import Enrollment
from teacher.serializers import CourseListSerializer

class StudentProgressSerializer(serializers.ModelSerializer):
    course_title = serializers.ReadOnlyField(source='course.title')
    student_name = serializers.ReadOnlyField(source='student.full_name')
    
    class Meta:
        model = StudentProgress
        fields = [
            'id', 'student', 'student_name', 'course', 'course_title',
            'last_accessed', 'completed', 'completion_date'
        ]
        read_only_fields = ['student', 'last_accessed', 'completed', 'completion_date']

class StudentNoteSerializer(serializers.ModelSerializer):
    section_title = serializers.ReadOnlyField(source='section.title')
    course_title = serializers.ReadOnlyField(source='section.course.title')
    
    class Meta:
        model = StudentNote
        fields = [
            'id', 'student', 'section', 'section_title', 'course_title',
            'content', 'created_at', 'updated_at'
        ]
        read_only_fields = ['student', 'created_at', 'updated_at']

class CertificateSerializer(serializers.ModelSerializer):
    student_name = serializers.ReadOnlyField(source='student.full_name')
    course_title = serializers.ReadOnlyField(source='course.title')
    
    class Meta:
        model = StudentCertificate
        fields = [
            'id', 'student', 'student_name', 'course', 'course_title',
            'issued_date', 'certificate_file', 'verification_code'
        ]
        read_only_fields = [
            'student', 'course', 'issued_date', 
            'certificate_file', 'verification_code'
        ]

class EnrollmentWithProgressSerializer(serializers.ModelSerializer):
    course = CourseListSerializer(read_only=True)
    progress_percentage = serializers.DecimalField(max_digits=5, decimal_places=2)
    last_activity = serializers.DateTimeField(read_only=True)
    
    class Meta:
        model = Enrollment
        fields = [
            'id', 'course', 'enrolled_at', 'is_active',
            'progress_percentage', 'completion_date',
            'sections_completed', 'quizzes_passed',
            'total_time_spent_minutes', 'last_activity'
        ]
        
        
from teacher.models import Course
# student/serializers.py
class TemporaryEnrollmentSerializer(serializers.Serializer):
    course_id = serializers.IntegerField()
    
    def validate_course_id(self, value):
        try:
            course = Course.objects.get(id=value)
            return value
        except Course.DoesNotExist:
            raise serializers.ValidationError("Course not found")

class BulkTemporaryEnrollmentSerializer(serializers.Serializer):
    course_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1
    )
    
    def validate_course_ids(self, value):
        valid_course_ids = []
        invalid_course_ids = []
        
        for course_id in value:
            if Course.objects.filter(id=course_id).exists():
                valid_course_ids.append(course_id)
            else:
                invalid_course_ids.append(course_id)
        
        if invalid_course_ids:
            raise serializers.ValidationError(
                f"Invalid course IDs: {invalid_course_ids}"
            )
        
        return valid_course_ids
    
    
from .models import Payment

class PaymentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Payment
        fields = '__all__'