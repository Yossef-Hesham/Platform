from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from account.models import User
from teacher.models import Course, Section, Quiz

class StudentProgress(models.Model):
    """Track student progress across all courses"""
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='student_progress'
    )
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='student_progress')
    last_accessed = models.DateTimeField(auto_now=True)
    completed = models.BooleanField(default=False)
    completion_date = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['student', 'course']
    
    def __str__(self):
        return f"{self.student.full_name} - {self.course.title}"

class StudentCertificate(models.Model):
    """Store certificates for completed courses"""
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='certificates'
    )
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='certificates')
    issued_date = models.DateTimeField(auto_now_add=True)
    certificate_file = models.URLField(max_length=500, null=True, blank=True)
    verification_code = models.CharField(max_length=100, unique=True)
    
    class Meta:
        unique_together = ['student', 'course']
    
    def __str__(self):
        return f"Certificate for {self.student.full_name} - {self.course.title}"

class StudentNote(models.Model):
    """Allow students to take notes on course sections"""
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='notes'
    )
    section = models.ForeignKey(Section, on_delete=models.CASCADE, related_name='notes')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['student', 'section']
    
    def __str__(self):
        return f"Note by {self.student.full_name} on {self.section.title}"
    
class Payment(models.Model):

    class choices(models.TextChoices):
        instapay = 'instapay', 'Instapay'
        vodafone_cash = 'vodafone cash', 'Vodafone Cash'
        orange_cash = 'orange cash', 'Orange Cash'
    
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='student_payments')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='course_payments')
    payment_method = models.CharField(max_length=20, choices=choices.choices)
    payment_date = models.DateTimeField(auto_now_add=True)
    
