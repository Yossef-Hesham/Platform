# models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
from django.utils import timezone


class User(AbstractUser):
    """
    Custom user model extending Django's AbstractUser
    """
    USER_TYPE_CHOICES = [
        ('student', 'Student'),
        ('teacher', 'Teacher'),
        ('parent', 'Parent'),
        ('admin', 'Admin'),
    ]
    
    user_type = models.CharField(
        max_length=10,
        choices=USER_TYPE_CHOICES,
        default='student'
    )
    
    # Additional fields
    phone_number = models.CharField(
        max_length=15,
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',
            message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        )],
        blank=False,
        null=True
    )
    
    profile_picture = models.ImageField(
        upload_to='profile_pictures/',
        blank=True,
        null=True
    )
    
    date_of_birth = models.DateField(blank=False, null=True)
    bio = models.TextField(max_length=500, blank=True)
    
    # Address fields
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    
    # Account status
    email_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Parent-student relationship
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        limit_choices_to={'user_type': 'parent'},
        related_name='children'
    )
    
    def __str__(self):
        return f"{self.username} ({self.get_user_type_display()})"
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    @property
    def is_teacher(self):
        return self.user_type == 'teacher'
    
    @property
    def is_student(self):
        return self.user_type == 'student'
    
    @property
    def is_parent(self):
        return self.user_type == 'parent'
    
    @property
    def is_admin(self):
        return self.user_type == 'admin'


class TeacherProfile(models.Model):
    """
    Extended profile for teachers
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'teacher'},
        related_name='teacher_profile'
    )
    
    specialization = models.CharField(max_length=200)
    experience_years = models.PositiveIntegerField(default=0)
    education = models.TextField(blank=True)
    certifications = models.TextField(blank=True)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    
    # Approval system for teachers
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        limit_choices_to={'user_type': 'admin'},
        related_name='approved_teachers'
    )
    approved_at = models.DateTimeField(blank=True, null=True)
    
    # Social links
    linkedin_url = models.URLField(blank=True)
    website_url = models.URLField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Teacher: {self.user.full_name}"
    
    def approve(self, admin_user):
        """Approve teacher by admin"""
        self.is_approved = True
        self.approved_by = admin_user
        self.approved_at = timezone.now()
        self.save()

class StudentProfile(models.Model):
    """
    Extended profile for students
    """
    GRADE_CHOICES = [
        ('kindergarten', 'Kindergarten'),
        ('grade_1', 'Grade 1'),
        ('grade_2', 'Grade 2'),
        ('grade_3', 'Grade 3'),
        ('grade_4', 'Grade 4'),
        ('grade_5', 'Grade 5'),
        ('grade_6', 'Grade 6'),
        ('grade_7', 'Grade 7'),
        ('grade_8', 'Grade 8'),
        ('grade_9', 'Grade 9'),
        ('grade_10', 'Grade 10'),
        ('grade_11', 'Grade 11'),
        ('grade_12', 'Grade 12'),
        ('college', 'College'),
        ('adult_learner', 'Adult Learner'),
    ]
    
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='student_profile'
    )
    
    grade_level = models.CharField(
        max_length=20,
        choices=GRADE_CHOICES,
        blank=True
    )
    
    school_name = models.CharField(max_length=200, blank=True)
    learning_goals = models.TextField(blank=True)
    interests = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Student: {self.user.full_name}"


class ParentProfile(models.Model):
    """
    Extended profile for parents
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'parent'},
        related_name='parent_profile'
    )
    
    occupation = models.CharField(max_length=200, blank=True)
    emergency_contact = models.CharField(max_length=15, blank=True)
    
    # Notification preferences
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Parent: {self.user.full_name}"
    
    def get_children(self):
        """Get all children associated with this parent"""
        return self.user.children.all()


class EmailVerification(models.Model):
    """
    Email verification tokens
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Email verification for {self.user.username}"
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class TEST(models.Model):
    txt = models.CharField(max_length=100)
    image = models.FileField(upload_to='test_photos/', null=True, blank=True)

class PasswordResetToken(models.Model):
    """
    Password reset tokens
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Password reset for {self.user.username}"
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at