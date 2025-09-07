# student/signals.py
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from teacher.models import Enrollment
from .models import (
    Payment, StudentQuizAttempt, CourseProgress, 
    StudentNotification, Certificate
)

