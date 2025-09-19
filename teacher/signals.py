# teacher/signals.py
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import (
    Section, Quiz, Enrollment, QuizAttempt, SectionView
)


@receiver(post_save, sender=Section)
@receiver(post_delete, sender=Section)
def update_course_sections_count(sender, instance, **kwargs):
    """Update course statistics when sections are added/removed"""
    instance.course.update_statistics()


@receiver(post_save, sender=Quiz)
@receiver(post_delete, sender=Quiz)
def update_course_quizzes_count(sender, instance, **kwargs):
    """Update course statistics when quizzes are added/removed"""
    instance.section.course.update_statistics()


@receiver(post_save, sender=Enrollment)
def update_course_enrollments_count(sender, instance, created, **kwargs):
    """Update course statistics when enrollments change"""
    if created or 'is_active' in (kwargs.get('update_fields') or []):
        instance.course.update_statistics()


@receiver(post_save, sender=QuizAttempt)
def update_quiz_statistics(sender, instance, created, **kwargs):
    """Update quiz statistics when attempts are completed"""
    if not created and instance.is_completed and 'is_completed' in (kwargs.get('update_fields') or []):
        instance.quiz.update_statistics()
        
        # Update enrollment quiz statistics
        try:
            enrollment = Enrollment.objects.get(
                student=instance.student,
                course=instance.quiz.section.course,
                is_active=True
            )
            
            if instance.is_passed:
                # Count total passed quizzes for this student in this course
                passed_quizzes = QuizAttempt.objects.filter(
                    student=instance.student,
                    quiz__section__course=enrollment.course,
                    is_passed=True
                ).values('quiz').distinct().count()
                
                enrollment.quizzes_passed = passed_quizzes
                enrollment.save(update_fields=['quizzes_passed'])
                
        except Enrollment.DoesNotExist:
            pass


@receiver(post_save, sender=SectionView)
def update_enrollment_progress(sender, instance, created, **kwargs):
    """Update enrollment progress when section views change"""
    if not created and 'is_completed' in (kwargs.get('update_fields') or []):
        try:
            enrollment = Enrollment.objects.get(
                student=instance.student,
                course=instance.section.course,
                is_active=True
            )
            enrollment.update_progress()
        except Enrollment.DoesNotExist:
            pass
        
    


@receiver(post_save, sender=SectionView)
def update_section_view_count(sender, instance, created, **kwargs):
    """Update section total views count"""
    if created:
        section = instance.section
        section.total_views = section.views.count()
        section.save(update_fields=['total_views'])
        
        # Update course total views
        course = section.course
        course.total_views = sum([s.total_views for s in course.sections.all()])
        course.save(update_fields=['total_views'])