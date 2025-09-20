# teacher/models.py
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from account.models import User
from cloudinary.models import CloudinaryField


class Course(models.Model):
    """
    Course model for teachers to create courses
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('published', 'Published'),
        ('archived', 'Archived'),
    ]
    
    DIFFICULTY_CHOICES = [
        ('beginner', 'Beginner'),
        ('intermediate', 'Intermediate'),
        ('advanced', 'Advanced'),
    ]
    
    # must be unique , do not forget to do it
    title = models.CharField(max_length=200, unique=True)
    description = models.TextField()
    teacher = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'teacher'},
        related_name='courses'
    )
    thumbnail = CloudinaryField('thumbnail', blank=True, null=True, folder='courses/thumbnails/')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    difficulty = models.CharField(max_length=20, choices=DIFFICULTY_CHOICES, default='beginner')
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    duration_hours = models.PositiveIntegerField(default=0)
    
    # Course metadata
    total_sections = models.PositiveIntegerField(default=0)
    total_quizzes = models.PositiveIntegerField(default=0)
    total_enrollments = models.PositiveIntegerField(default=0)
    total_views = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} - {self.teacher.full_name}"
    
    def update_statistics(self):
        """Update course statistics"""
        self.total_sections = self.sections.count()
        self.total_quizzes = Quiz.objects.filter(section__course=self).count()
        self.total_enrollments = self.enrollments.filter(is_active=True).count()
        self.save(update_fields=['total_sections', 'total_quizzes', 'total_enrollments'])


class Section(models.Model):
    """
    Section model for course content
    """
    CONTENT_TYPE_CHOICES = [
        ('video', 'Video'),
        ('text', 'Text'),
        ('pdf', 'PDF'),
        ('mixed', 'Mixed Content'),
    ]
    
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='sections')
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    content_type = models.CharField(max_length=20, choices=CONTENT_TYPE_CHOICES, default='text')
    content = models.TextField(blank=True)  # For text content
    
    video_file = CloudinaryField(
        resource_type='video',
        blank=True,
        null=True,
        folder='courses/videos/',
        use_filename=True,
        transformation=[
            {'quality': 'auto'},
            {'format': 'mp4'},  # Convert to MP4 for compatibility
        ]
    )

    pdf_file = CloudinaryField('pdf', blank=True, null=True, folder='courses/pdfs/')
    order = models.PositiveIntegerField(default=0)
    duration_minutes = models.PositiveIntegerField(default=0)
    
    # Section statistics
    total_views = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['order']
        unique_together = ['course', 'order']
    
    def __str__(self):
        return f"{self.course.title} - Section {self.order}: {self.title}"


class Quiz(models.Model):
    """
    Quiz model for sections
    """
    section = models.OneToOneField(Section, on_delete=models.CASCADE, related_name='quiz')
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    time_limit_minutes = models.PositiveIntegerField(default=30)
    passing_score = models.PositiveIntegerField(default=70, validators=[MinValueValidator(0), MaxValueValidator(100)])
    max_attempts = models.PositiveIntegerField(default=3)
    shuffle_questions = models.BooleanField(default=True)
    
    # Quiz statistics
    total_attempts = models.PositiveIntegerField(default=0)
    average_score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Quiz: {self.title} ({self.section.course.title})"
    
    def update_statistics(self):
        """Update quiz statistics"""
        attempts = self.attempts.filter(is_completed=True)
        self.total_attempts = attempts.count()
        if self.total_attempts > 0:
            avg_score = attempts.aggregate(models.Avg('score'))['score__avg']
            self.average_score = round(avg_score, 2) if avg_score else 0.00
        self.save(update_fields=['total_attempts', 'average_score'])


class Question(models.Model):
    """
    Question model for quizzes
    """
    QUESTION_TYPE_CHOICES = [
        ('multiple_choice', 'Multiple Choice'),
        ('true_false', 'True/False'),
        ('short_answer', 'Short Answer'),
    ]
    
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    question_text = models.TextField()
    question_type = models.CharField(max_length=20, choices=QUESTION_TYPE_CHOICES, default='multiple_choice')
    points = models.PositiveIntegerField(default=1)
    order = models.PositiveIntegerField(default=0)
    explanation = models.TextField(blank=True)  # Explanation for the correct answer
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['order']
        unique_together = ['quiz', 'order']
    
    def __str__(self):
        return f"Q{self.order}: {self.question_text[:50]}..."


class Choice(models.Model):
    """
    Choice model for multiple choice questions
    """
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='choices')
    choice_text = models.CharField(max_length=500)
    is_correct = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['order']
    
    def __str__(self):
        return f"{self.choice_text} ({'Correct' if self.is_correct else 'Incorrect'})"

from django.db.models import Sum

class Enrollment(models.Model):
    """
    Student enrollment in courses
    """
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='enrollments'
    )
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='enrollments')
    enrolled_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    progress_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    completion_date = models.DateTimeField(blank=True, null=True)
    
    # Enrollment statistics
    total_time_spent_minutes = models.PositiveIntegerField(default=0)
    sections_completed = models.PositiveIntegerField(default=0)
    quizzes_passed = models.PositiveIntegerField(default=0)
    
    class Meta:
        unique_together = ['student', 'course']
        ordering = ['-enrolled_at']
    
    def __str__(self):
        return f"{self.student.full_name} enrolled in {self.course.title}"
    
    def update_progress(self):
        """Recalculate and update progress metrics"""
        # Count completed sections in this course
        completed_sections = SectionView.objects.filter(
            student=self.student,
            section__course=self.course,
            is_completed=True
        ).count()
        
        total_sections = self.course.sections.count()
        
        # Calculate progress percentage
        if total_sections > 0:
            progress_percentage = (completed_sections / total_sections) * 100
        else:
            progress_percentage = 0
        
        # Count passed quizzes (distinct quizzes passed)
        passed_quizzes = QuizAttempt.objects.filter(
            student=self.student,
            quiz__section__course=self.course,
            is_passed=True
        ).values('quiz').distinct().count()
        
        # Calculate total time spent
        total_time = SectionView.objects.filter(
            student=self.student,
            section__course=self.course
        ).aggregate(total_time=Sum('total_time_spent_minutes'))['total_time'] or 0
        
        # Update fields
        self.sections_completed = completed_sections
        self.progress_percentage = progress_percentage
        self.quizzes_passed = passed_quizzes
        self.total_time_spent_minutes = total_time
        self.save()

class SectionView(models.Model):
    """
    Track student views of course sections
    """
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='section_views'
    )
    section = models.ForeignKey(Section, on_delete=models.CASCADE, related_name='views')
    first_viewed_at = models.DateTimeField(auto_now_add=True)
    last_viewed_at = models.DateTimeField(auto_now=True)
    total_time_spent_minutes = models.PositiveIntegerField(default=0)
    is_completed = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['student', 'section']
        ordering = ['-last_viewed_at']
    
    def __str__(self):
        return f"{self.student.full_name} viewed {self.section.title}"


class QuizAttempt(models.Model):
    """
    Student quiz attempts
    """
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='quiz_attempts'
    )
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='attempts')
    attempt_number = models.PositiveIntegerField(default=1)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    is_completed = models.BooleanField(default=False)
    score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    total_points = models.PositiveIntegerField(default=0)
    earned_points = models.PositiveIntegerField(default=0)
    time_spent_minutes = models.PositiveIntegerField(default=0)
    is_passed = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['student', 'quiz', 'attempt_number']
        ordering = ['-started_at']
    
    def __str__(self):
        return f"{self.student.full_name} - {self.quiz.title} (Attempt {self.attempt_number})"
    
    def calculate_score(self):
        """Calculate quiz score based on answers"""
        total_points = sum([answer.question.points for answer in self.answers.all()])
        earned_points = sum([answer.question.points for answer in self.answers.filter(is_correct=True)])
        
        self.total_points = total_points
        self.earned_points = earned_points
        self.score = (earned_points / total_points * 100) if total_points > 0 else 0
        self.is_passed = self.score >= self.quiz.passing_score
        
        self.save(update_fields=['total_points', 'earned_points', 'score', 'is_passed'])


class QuizAnswer(models.Model):
    """
    Student answers to quiz questions
    """
    attempt = models.ForeignKey(QuizAttempt, on_delete=models.CASCADE, related_name='answers')
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    selected_choice = models.ForeignKey(Choice, on_delete=models.CASCADE, blank=True, null=True)
    text_answer = models.TextField(blank=True)  # For short answer questions
    is_correct = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['attempt', 'question']
    
    def __str__(self):
        return f"Answer to {self.question.question_text[:30]}..."
    
    def save(self, *args, **kwargs):
        # Automatically determine if answer is correct
        if self.question.question_type == 'multiple_choice' and self.selected_choice:
            self.is_correct = self.selected_choice.is_correct
        elif self.question.question_type == 'true_false' and self.selected_choice:
            self.is_correct = self.selected_choice.is_correct
        # Short answer questions need manual grading
        
        super().save(*args, **kwargs)


class CourseReview(models.Model):
    """
    Student reviews for courses
    """
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'user_type': 'student'},
        related_name='course_reviews'
    )
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='reviews')
    rating = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    review_text = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['student', 'course']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.student.full_name} rated {self.course.title} - {self.rating} stars"
    


from django.conf import settings
class Review(models.Model):
    course = models.ForeignKey(
        Course,
        related_name="course_reviews",
        on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )
    rating = models.IntegerField(default=1)  # مثلا من 1 لـ 5
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('course', 'user')  # مستخدم واحد يعمل review واحد بس للكورس

    def __str__(self):
        return f"{self.user} - {self.course} ({self.rating})"
    
# models.py
class Notification(models.Model):
    TEACHER_TO_STUDENTS = 'teacher_students'
    TEACHER_TO_COURSE = 'teacher_course'
    SYSTEM = 'system'
    
    NOTIFICATION_TYPES = [
        (TEACHER_TO_STUDENTS, 'Teacher to specific students'),
        (TEACHER_TO_COURSE, 'Teacher to entire course'),
        (SYSTEM, 'System notification'),
    ]
    
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_notifications')
    recipients = models.ManyToManyField(User, related_name='received_notifications')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=200)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} - {self.sender.full_name}"