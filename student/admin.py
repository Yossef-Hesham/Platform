# student/admin.py
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.db.models import Q

# from .models import (
#     Payment, StudentQuizAttempt, StudentQuizAnswer, CourseProgress,
#     Certificate, DownloadHistory, SupportTicket, SupportMessage,
#     StudentNotification, WatchHistory
# )



from .models import StudentCertificate

@admin.register(StudentCertificate)
class StudentCertificateAdmin(admin.ModelAdmin):
    # Display fields in list view
    list_display = [
        'student_full_name', 
        'course_title', 
        'issued_date', 
        'verification_code_short',
        'has_certificate_file'
    ]
    
    # Filters in the sidebar
    list_filter = [
        'issued_date',
        'course',
    ]
    
    # Search functionality
    search_fields = [
        'student__full_name',
        'student__email',
        'course__title',
        'verification_code'
    ]
    
    # Read-only fields
    readonly_fields = [
        'issued_date',
        'verification_code',
        'certificate_preview'
    ]
    
    # Date hierarchy for navigation
    date_hierarchy = 'issued_date'
    
    # Fields to display in detail view
    fieldsets = (
        ('Student Information', {
            'fields': ('student', 'student_full_name')
        }),
        ('Course Information', {
            'fields': ('course', 'course_title')
        }),
        ('Certificate Details', {
            'fields': (
                'issued_date',
                'verification_code',
                'certificate_file',
                'certificate_preview'
            )
        }),
    )
    
    # Custom methods for list display
    def student_full_name(self, obj):
        return obj.student.full_name
    student_full_name.short_description = 'Student Name'
    student_full_name.admin_order_field = 'student__full_name'
    
    def course_title(self, obj):
        return obj.course.title
    course_title.short_description = 'Course Title'
    course_title.admin_order_field = 'course__title'
    
    def verification_code_short(self, obj):
        return obj.verification_code[:8] + '...' if len(obj.verification_code) > 8 else obj.verification_code
    verification_code_short.short_description = 'Verification Code'
    
    def has_certificate_file(self, obj):
        return bool(obj.certificate_file)
    has_certificate_file.boolean = True
    has_certificate_file.short_description = 'File Uploaded'
    
    def certificate_preview(self, obj):
        if obj.certificate_file:
            return f'<a href="{obj.certificate_file}" target="_blank">View Certificate</a>'
        return "No certificate file available"
    certificate_preview.allow_tags = True
    certificate_preview.short_description = 'Certificate Preview'