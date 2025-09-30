from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from teacher.models import Course, Section, Quiz, Enrollment, QuizAttempt, SectionView
from teacher.serializers import CourseDetailSerializer, SectionSerializer, QuizSerializer
from .models import StudentProgress, StudentNote, StudentCertificate
from .serializers import StudentProgressSerializer, StudentNoteSerializer, CertificateSerializer
from gateway.models import Order
from .serializers import *
from teacher.models import *
from django.utils import timezone
from django.db.models import Sum, Avg,Prefetch, Max
from datetime import timedelta
from django.http import HttpResponse
from django.http import FileResponse
from django.core.files.storage import default_storage
import os
import uuid
import logging
from io import BytesIO
from django.conf import settings
from django.core.files.base import ContentFile
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import registerFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.utils import ImageReader
import cloudinary
import cloudinary.uploader
import requests


class IsStudent(permissions.BasePermission):
    """Check if user is a student"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_student



from rest_framework.permissions import AllowAny

from rest_framework.generics import ListAPIView

class GETAllCourses(ListAPIView):
    serializer_class = CourseListSerializer
    queryset = Course.objects.all()
    permission_classes = [AllowAny]  # Allow any user to view the list of courses




class StudentDashboardView(APIView):
    """Student dashboard overview"""
    permission_classes = [IsStudent]
    
    def get(self, request):
        student = request.user
        
        # Get enrolled courses
        enrollments = Enrollment.objects.filter(
            student=student, 
            is_active=True
        ).select_related('course')
        
        # Get in-progress courses (progress < 100%)
        in_progress_courses = [
            enrollment for enrollment in enrollments 
            if enrollment.progress_percentage < 100
        ]
        
        # Get completed courses
        completed_courses = [
            enrollment for enrollment in enrollments 
            if enrollment.progress_percentage >= 100
        ]
        
        # Get recent activity
        recent_sections = SectionView.objects.filter(
            student=student
        ).order_by('-last_viewed_at')[:5]
        
        # Get upcoming quizzes (if any)
        # This would require additional logic based on course structure
        
        return Response({
            'in_progress_courses': len(in_progress_courses),
            'completed_courses': len(completed_courses),
            'recent_activity': [
                {
                    'section_title': view.section.title,
                    'course_title': view.section.course.title,
                    'last_viewed': view.last_viewed_at
                } for view in recent_sections
            ]
        })

class MyCoursesView(generics.ListAPIView):
    """List all courses enrolled by the student"""
    permission_classes = [IsStudent]
    serializer_class = CourseDetailSerializer
    
    def get_queryset(self):
        student = self.request.user
        return Course.objects.filter(
            enrollments__student=student,
            enrollments__is_active=True
        ).prefetch_related(
            Prefetch('sections'),
            Prefetch('reviews')
        )

class CourseContentView(APIView):
    """Get course content for a specific course"""
    permission_classes = [IsStudent]
    
    def get(self, request, course_id):
        student = request.user
        
        # Check if student is enrolled in the course
        enrollment = get_object_or_404(
            Enrollment, 
            student=student, 
            course_id=course_id,
            is_active=True
        )
        
        course = enrollment.course
        sections = course.sections.all().order_by('order')
        
        # Get student's progress on each section
        section_data = []
        for section in sections:
            section_view = SectionView.objects.filter(
                student=student,
                section=section
            ).first()
            
            section_data.append({
                'section': SectionSerializer(section).data,
                'completed': section_view.is_completed if section_view else False,
                'last_viewed': section_view.last_viewed_at if section_view else None
            })
        
        return Response({
            'course': CourseDetailSerializer(course).data,
            'sections': section_data,
            'overall_progress': enrollment.progress_percentage
        })
class SectionDetailView(APIView):
    """Get section content by course ID and section order"""
    permission_classes = [IsStudent]
    
    def get(self, request, course_id, section_order):
        student = request.user
        course = get_object_or_404(Course, id=course_id)
        
        # Check if student is enrolled in the course
        enrollment = get_object_or_404(
            Enrollment, 
            student=student, 
            course=course,
            is_active=True
        )
        
        # Get section by order
        section = get_object_or_404(
            Section, 
            course=course, 
            order=section_order
        )
        
        # Create or update section view
        section_view, created = SectionView.objects.get_or_create(
            student=student,
            section=section,
            defaults={'is_completed': False}
        )
        
        if not created:
            section_view.save()  # Updates last_viewed_at
            
        # Get student notes for this section
        note = StudentNote.objects.filter(
            student=student,
            section=section
        ).first()
        
        # Get next and previous sections for navigation
        next_section = Section.objects.filter(
            course=course,
            order__gt=section_order
        ).order_by('order').first()
        
        previous_section = Section.objects.filter(
            course=course,
            order__lt=section_order
        ).order_by('-order').first()
        
        return Response({
            'section': SectionSerializer(section).data,
            'note': StudentNoteSerializer(note).data if note else None,
            'viewed': True,
            'completed': section_view.is_completed,
            'navigation': {
                'next_section': next_section.id if next_section else None,
                'previous_section': previous_section.id if previous_section else None,
                'current_order': section_order,
                'total_sections': course.sections.count()
            }
        })
    
    def post(self, request, course_id, section_order):
        # Mark section as completed
        student = request.user
        course = get_object_or_404(Course, id=course_id)
        
        # Check if student is enrolled in the course
        enrollment = get_object_or_404(
            Enrollment, 
            student=student, 
            course=course,
            is_active=True
        )
        
        # Get section by order
        section = get_object_or_404(
            Section, 
            course=course, 
            order=section_order
        )
        
        section_view = get_object_or_404(
            SectionView,
            student=student,
            section=section
        )
        
        section_view.is_completed = True
        section_view.save()
        
        # Update enrollment progress
        enrollment.update_progress()
        
        # Check if course is completed
        if enrollment.progress_percentage >= 100:
            # Generate certificate if not already exists
            certificate, created = StudentCertificate.objects.get_or_create(
                student=student,
                course=course,
                defaults={'verification_code': self.generate_certificate_pdf()}
            )
            
            return Response({
                'status': 'section marked as completed',
                'course_completed': True,
                'certificate_id': certificate.id
            })
        
        return Response({
            'status': 'section marked as completed',
            'course_completed': False
        })
        
from django.db import transaction
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class TakeQuizView(APIView):
    """Start and submit a quiz attempt"""
    permission_classes = [IsStudent]
    
    def get(self, request, course_id, section_id, quiz_id):
        student = request.user
        
        section = get_object_or_404(Section, id=section_id, course_id=course_id)
        quiz = get_object_or_404(Quiz, section=section, id=quiz_id)

        # Check if student is enrolled in the course
        enrollment = get_object_or_404(
            Enrollment, 
            student=student, 
            course=quiz.section.course,
            is_active=True
        )
        
        # Check if student has attempts remaining (atomic operation)
        previous_attempts = QuizAttempt.objects.filter(
            student=student,
            quiz=quiz
        ).count()
        
        if previous_attempts >= quiz.max_attempts:
            return Response(
                {'error': 'No attempts remaining for this quiz'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create a new quiz attempt
        attempt = QuizAttempt.objects.create(
            student=student,
            quiz=quiz,
            attempt_number=previous_attempts + 1,
            started_at=timezone.now()
        )
        
        # Get quiz questions (without correct answers)
        questions = quiz.questions.all().order_by('order')
        question_data = []
        
        for question in questions:
            question_dict = {
                'id': question.id,
                'question_text': question.question_text,
                'question_type': question.question_type,
                'points': question.points,
                'order': question.order
            }
            
            if question.question_type in ['multiple_choice', 'true_false', 'multiple_answer']:
                choices = question.choices.all().order_by('order')
                question_dict['choices'] = [
                    {'id': choice.id, 'choice_text': choice.choice_text}
                    for choice in choices
                ]
            
            question_data.append(question_dict)
        
        return Response({
            'attempt_id': attempt.id,
            'quiz_title': quiz.title,
            'time_limit_minutes': quiz.time_limit_minutes,
            'questions': question_data,
            'started_at': attempt.started_at
        })
    
    def post(self, request, course_id, section_id, quiz_id):
        """Submit quiz answers"""
        student = request.user
        
        # First get the section and quiz to verify they exist
        section = get_object_or_404(Section, id=section_id, course_id=course_id)
        quiz = get_object_or_404(Quiz, section=section, id=quiz_id)
        
        attempt_id = request.data.get('attempt_id')
        
        if not attempt_id:
            return Response(
                {'error': 'attempt_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Debug: Print attempt details
        print(f"Looking for attempt: {attempt_id}, student: {student.id}, quiz: {quiz_id}")
        
        # First try to find the attempt with all conditions
        try:
            attempt = QuizAttempt.objects.get(
                id=attempt_id,
                student=student,
                quiz=quiz,
                is_completed=False
            )
        except QuizAttempt.DoesNotExist:
            # If not found, check if it exists but is completed
            try:
                completed_attempt = QuizAttempt.objects.get(
                    id=attempt_id,
                    student=student,
                    quiz=quiz
                )
                if completed_attempt.is_completed:
                    return Response(
                        {'error': 'This quiz attempt has already been submitted'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    # This shouldn't happen, but if it does, use this attempt
                    attempt = completed_attempt
            except QuizAttempt.DoesNotExist:
                # Check if the attempt exists but belongs to different quiz or user
                try:
                    # Check if attempt exists with different quiz
                    wrong_quiz_attempt = QuizAttempt.objects.get(
                        id=attempt_id,
                        student=student
                    )
                    return Response(
                        {'error': f'Attempt belongs to quiz ID {wrong_quiz_attempt.quiz.id}, not {quiz_id}'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                except QuizAttempt.DoesNotExist:
                    try:
                        # Check if attempt exists with different user
                        wrong_user_attempt = QuizAttempt.objects.get(id=attempt_id)
                        return Response(
                            {'error': 'This attempt belongs to another user'},
                            status=status.HTTP_403_FORBIDDEN
                        )
                    except QuizAttempt.DoesNotExist:
                        # Attempt doesn't exist at all
                        return Response(
                            {'error': 'Quiz attempt not found. Please start the quiz first.'},
                            status=status.HTTP_404_NOT_FOUND
                        )
    
    # Check time limit
        time_elapsed = (timezone.now() - attempt.started_at).total_seconds() / 60
        if time_elapsed > quiz.time_limit_minutes:
            return Response(
                {'error': 'Time limit exceeded'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        answers = request.data.get('answers', [])
        
        # Process each answer within a transaction
        try:
            with transaction.atomic():
                for answer_data in answers:
                    question_id = answer_data.get('question_id')
                    if not question_id:
                        continue
                    
                    question = get_object_or_404(Question, id=question_id, quiz=quiz)
                    
                    if question.question_type in ['multiple_choice', 'true_false']:
                        choice_id = answer_data.get('choice_id')
                        if choice_id:
                            selected_choice = get_object_or_404(Choice, id=choice_id, question=question)
                            QuizAnswer.objects.create(
                                attempt=attempt,
                                question=question,
                                selected_choice=selected_choice
                            )
                    
                    elif question.question_type == 'multiple_answer':
                        choice_ids = answer_data.get('choice_ids', [])
                        for choice_id in choice_ids:
                            selected_choice = get_object_or_404(Choice, id=choice_id, question=question)
                            QuizAnswer.objects.create(
                                attempt=attempt,
                                question=question,
                                selected_choice=selected_choice
                            )
                    
                    else:  # text answer questions
                        text_answer = answer_data.get('text_answer', '')
                        QuizAnswer.objects.create(
                            attempt=attempt,
                            question=question,
                            text_answer=text_answer
                        )
                
                # Complete the attempt and calculate score
                attempt.is_completed = True
                attempt.completed_at = timezone.now()
                attempt.calculate_score()  # Make sure this method exists in your model
                attempt.save()
                
                # Update enrollment quiz statistics
                enrollment = Enrollment.objects.get(
                    student=student,
                    course=quiz.section.course,
                    is_active=True
                )
                
                if attempt.is_passed:
                    passed_quizzes = QuizAttempt.objects.filter(
                        student=student,
                        quiz__section__course=enrollment.course,
                        is_passed=True
                    ).values('quiz').distinct().count()
                    
                    enrollment.quizzes_passed = passed_quizzes
                    enrollment.save(update_fields=['quizzes_passed'])
        
        except Exception as e:
            return Response(
                {'error': f'Error processing answers: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response({
            'attempt_id': attempt.id,
            'score': attempt.score,
            'is_passed': attempt.is_passed,
            'correct_answers': attempt.earned_points,
            'total_questions': attempt.total_points,
            'time_taken_minutes': round(time_elapsed, 2),
            'message': 'Quiz submitted successfully'
        })
    def calculate_score(self):
        """Calculate the score for this attempt"""
        answers = self.answers.all()
        total_points = 0
        earned_points = 0
        
        for answer in answers:
            total_points += answer.question.points
            
            if answer.question.question_type in ['multiple_choice', 'true_false']:
                if answer.selected_choice and answer.selected_choice.is_correct:
                    earned_points += answer.question.points
            
            elif answer.question.question_type == 'multiple_answer':
                # For multiple answer, all correct choices must be selected
                correct_choices = answer.question.choices.filter(is_correct=True)
                selected_correct = answer.selected_choices.filter(is_correct=True)
                if correct_choices.count() == selected_correct.count() == answer.selected_choices.count():
                    earned_points += answer.question.points
            
            # For text answers, you might need manual grading
            # else:
            #     # Text answers typically require manual grading
            #     pass
        
        self.earned_points = earned_points
        self.total_points = total_points
        self.score = (earned_points / total_points * 100) if total_points > 0 else 0
        self.is_passed = self.score >= self.quiz.passing_score
    
    # Rest of your submission code...
class QuizResultsView(APIView):
    """View quiz results and correct answers"""
    permission_classes = [IsStudent]
    
    def get(self, request, attempt_id):
        student = request.user
        attempt = get_object_or_404(
            QuizAttempt, 
            id=attempt_id, 
            student=student,
            is_completed=True
        )
        
        # Get detailed results
        answers = attempt.answers.all().select_related('question', 'selected_choice')
        results = []
        
        for answer in answers:
            question = answer.question
            correct_answer = None
            
            if question.question_type in ['multiple_choice', 'true_false']:
                correct_choice = question.choices.filter(is_correct=True).first()
                correct_answer = correct_choice.choice_text if correct_choice else None
            
            results.append({
                'question': question.question_text,
                'question_type': question.question_type,
                'your_answer': answer.selected_choice.choice_text if answer.selected_choice else answer.text_answer,
                'correct_answer': correct_answer,
                'is_correct': answer.is_correct,
                'points_earned': question.points if answer.is_correct else 0,
                'points_possible': question.points
            })
        
        return Response({
            'quiz_title': attempt.quiz.title,
            'score': attempt.score,
            'is_passed': attempt.is_passed,
            'time_spent_minutes': attempt.time_spent_minutes,
            'results': results
        })

class StudentNotesView(APIView):
    """Manage student notes"""
    permission_classes = [IsStudent]
    
    def get(self, request, section_id):
        student = request.user
        section = get_object_or_404(Section, id=section_id)
        
        # Check if student is enrolled in the course
        enrollment = get_object_or_404(
            Enrollment, 
            student=student, 
            course=section.course,
            is_active=True
        )
        
        note = StudentNote.objects.filter(
            student=student,
            section=section
        ).first()
        
        if note:
            return Response(StudentNoteSerializer(note).data)
        return Response({})
    
    def post(self, request, section_id):
        student = request.user
        section = get_object_or_404(Section, id=section_id)
        content = request.data.get('content', '')
        
        # Check if student is enrolled in the course
        enrollment = get_object_or_404(
            Enrollment, 
            student=student, 
            course=section.course,
            is_active=True
        )
        
        note, created = StudentNote.objects.update_or_create(
            student=student,
            section=section,
            defaults={'content': content}
        )
        
        return Response(StudentNoteSerializer(note).data)
    
    def delete(self, request, section_id):
        student = request.user
        section = get_object_or_404(Section, id=section_id)
        
        note = get_object_or_404(
            StudentNote,
            student=student,
            section=section
        )
        
        note.delete()
        return Response({'status': 'note deleted'})


# student/views.py
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch, cm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor
import os
from django.conf import settings
from io import BytesIO
from django.core.files.base import ContentFile
import uuid






class CertificateView2(APIView):
    """Get certificate for a completed course"""
    permission_classes = [IsStudent]
    
    def get(self, request, course_id):
        try:
            student = request.user
            course = get_object_or_404(Course, id=course_id)
            
            # Check if student has completed the course
            enrollment = get_object_or_404(
                Enrollment,
                student=student,
                course=course,
                is_active=True
            )
            
            if enrollment.progress_percentage < 100:
                return Response(
                    {
                        'error': 'Course not completed yet',
                        'progress': float(enrollment.progress_percentage),
                        'required': 100.0
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get or create certificate
            certificate, created = StudentCertificate.objects.get_or_create(
                student=student,
                course=course,
                defaults={
                    'verification_code': self.generate_verification_code(),
                    'issued_date': timezone.now()
                }
            )
            
            # Generate PDF certificate if not exists or needs regeneration
            if not certificate.certificate_file or self.needs_regeneration(certificate):
                try:
                    certificate.certificate_file = self.generate_certificate_pdf(certificate)
                    certificate.save()
                except Exception as e:
                    logger.error(f"Certificate generation failed: {e}")
                    return Response(
                        {'error': 'Failed to generate certificate. Please try again later.'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Check if file exists and is accessible
            if not certificate.certificate_file or not certificate.certificate_file.name:
                return Response(
                    {'error': 'Certificate file not available'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response({
                'certificate_url': request.build_absolute_uri(certificate.certificate_file.url),
                'download_url': f"/api/student/certificates/download/{certificate.id}/",
                'verification_code': certificate.verification_code,
                'issued_date': certificate.issued_date,
                'student_name': student.full_name,
                'course_title': course.title,
                'message': 'Certificate generated successfully' if created else 'Certificate retrieved successfully'
            })
            
        except Exception as e:
            logger.error(f"Certificate view error: {e}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def generate_verification_code(self):
        """Generate a unique verification code for certificates"""
        return str(uuid.uuid4()).replace('-', '')[:16].upper()
    
    def needs_regeneration(self, certificate):
        """Check if certificate needs to be regenerated"""
        # Regenerate if file doesn't exist on filesystem
        if not certificate.certificate_file or not os.path.exists(certificate.certificate_file.path):
            return True
        
        # Regenerate if issued date changed significantly
        if certificate.issued_date and (timezone.now() - certificate.issued_date).days > 30:
            return True
            
        return False
    
    def generate_certificate_pdf(self, certificate):
        """Generate PDF certificate using ReportLab"""
        try:
            # Create a buffer for the PDF
            buffer = BytesIO()
            
            # Create the PDF object
            c = canvas.Canvas(buffer, pagesize=letter)
            width, height = letter
            
            # Register fonts (you might need to add font files to your project)
            try:
                # Add these font files to your project or use system fonts
                font_path = os.path.join(settings.BASE_DIR, 'static', 'fonts')
                
                # Try to register custom fonts, fallback to standard fonts if not available
                if os.path.exists(os.path.join(font_path, 'OpenSans-Bold.ttf')):
                    pdfmetrics.registerFont(TTFont('OpenSans-Bold', os.path.join(font_path, 'OpenSans-Bold.ttf')))
                if os.path.exists(os.path.join(font_path, 'OpenSans-Regular.ttf')):
                    pdfmetrics.registerFont(TTFont('OpenSans-Regular', os.path.join(font_path, 'OpenSans-Regular.ttf')))
            except:
                pass  # Use standard fonts if custom fonts aren't available
            
            # Add background design or border
            self.draw_certificate_design(c, width, height)
            
            # Add certificate title
            c.setFillColor(HexColor('#2C3E50'))  # Dark blue
            c.setFont('Helvetica-Bold', 36)
            c.drawCentredString(width/2, height - 2*inch, "CERTIFICATE OF COMPLETION")
            
            # Add decorative line
            c.setStrokeColor(HexColor('#3498DB'))
            c.setLineWidth(2)
            c.line(width/2 - 2*inch, height - 2.3*inch, width/2 + 2*inch, height - 2.3*inch)
            
            # Add "This is to certify that"
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 18)
            c.drawCentredString(width/2, height - 3*inch, "This is to certify that")
            
            # Add student name
            c.setFillColor(HexColor('#2C3E50'))
            c.setFont('Helvetica-Bold', 28)
            student_name = certificate.student.full_name.upper()
            c.drawCentredString(width/2, height - 3.8*inch, student_name)
            
            # Add "has successfully completed the course"
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 18)
            c.drawCentredString(width/2, height - 4.6*inch, "has successfully completed the course")
            
            # Add course title
            c.setFillColor(HexColor('#E74C3C'))
            c.setFont('Helvetica-Bold', 22)
            course_title = certificate.course.title
            # Wrap text if too long
            if len(course_title) > 40:
                lines = self.wrap_text(course_title, 40)
                for i, line in enumerate(lines):
                    c.drawCentredString(width/2, height - (5.2 + i*0.4)*inch, line)
            else:
                c.drawCentredString(width/2, height - 5.2*inch, course_title)
            
            # Add completion date
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 14)
            completion_date = certificate.issued_date.strftime("%B %d, %Y")
            c.drawCentredString(width/2, height - 6.2*inch, f"Completed on: {completion_date}")
            
            # Add verification code
            c.setFillColor(HexColor('#95A5A6'))
            c.setFont('Helvetica-Oblique', 12)
            c.drawCentredString(width/2, height - 6.8*inch, f"Verification Code: {certificate.verification_code}")
            
            # Add platform URL
            c.setFillColor(HexColor('#BDC3C7'))
            c.setFont('Helvetica', 10)
            c.drawCentredString(width/2, 0.5*inch, "Verify at: https://yourplatform.com/verify-certificate/")
            
            # Add signatures area
            self.draw_signatures(c, width, height)
            
            # Save the PDF
            c.showPage()
            c.save()
            
            # Get PDF content from buffer
            pdf_content = buffer.getvalue()
            buffer.close()
            
            # Create filename
            filename = f"certificate_{certificate.verification_code}.pdf"
            filepath = f"certificates/{filename}"
            
            # Save to certificate model
            certificate.certificate_file.save(filename, ContentFile(pdf_content), save=False)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating certificate PDF: {e}")
            # Fallback to simple certificate
            return self.generate_simple_certificate(certificate)
    
    def draw_certificate_design(self, c, width, height):
        """Draw certificate background design"""
        # Add decorative border
        c.setStrokeColor(HexColor('#3498DB'))
        c.setLineWidth(3)
        c.rect(0.5*inch, 0.5*inch, width - 1*inch, height - 1*inch)
        
        # Add decorative corners
        corner_size = 0.3*inch
        corners = [
            (0.5*inch, 0.5*inch),  # bottom-left
            (0.5*inch, height - 0.5*inch),  # top-left
            (width - 0.5*inch, 0.5*inch),  # bottom-right
            (width - 0.5*inch, height - 0.5*inch)  # top-right
        ]
        
        for x, y in corners:
            c.setLineWidth(2)
            c.line(x, y, x + corner_size, y)
            c.line(x, y, x, y + corner_size)
        
        # Add watermark (optional)
        try:
            watermark_path = os.path.join(settings.BASE_DIR, 'static', 'images', 'watermark.png')
            if os.path.exists(watermark_path):
                watermark = ImageReader(watermark_path)
                c.drawImage(watermark, width/2 - 1*inch, height/2 - 1*inch, 
                           width=2*inch, height=2*inch, mask='auto')
        except:
            pass
    
    def draw_signatures(self, c, width, height):
        """Draw signature lines"""
        # Instructor signature
        c.setStrokeColor(HexColor('#7F8C8D'))
        c.setLineWidth(1)
        c.line(width/4 - 1.5*inch, 1.5*inch, width/4 + 1.5*inch, 1.5*inch)
        c.setFillColor(HexColor('#7F8C8D'))
        c.setFont('Helvetica', 12)
        c.drawCentredString(width/4, 1.2*inch, "Instructor Signature")
        
        # Platform signature
        c.line(3*width/4 - 1.5*inch, 1.5*inch, 3*width/4 + 1.5*inch, 1.5*inch)
        c.drawCentredString(3*width/4, 1.2*inch, "Platform Seal")
    
    def wrap_text(self, text, max_length):
        """Wrap text into multiple lines if too long"""
        words = text.split()
        lines = []
        current_line = []
        
        for word in words:
            if len(' '.join(current_line + [word])) <= max_length:
                current_line.append(word)
            else:
                lines.append(' '.join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
    def generate_simple_certificate(self, certificate):
        """Fallback function for simple certificate generation"""
        try:
            buffer = BytesIO()
            c = canvas.Canvas(buffer, pagesize=letter)
            width, height = letter
            
            # Simple certificate design
            c.setFont('Helvetica-Bold', 24)
            c.drawCentredString(width/2, height - 2*inch, "CERTIFICATE OF COMPLETION")
            
            c.setFont('Helvetica', 16)
            c.drawCentredString(width/2, height - 3*inch, "This certifies that")
            
            c.setFont('Helvetica-Bold', 20)
            c.drawCentredString(width/2, height - 3.5*inch, certificate.student.full_name.upper())
            
            c.setFont('Helvetica', 16)
            c.drawCentredString(width/2, height - 4.5*inch, "has successfully completed")
            
            c.setFont('Helvetica-Bold', 18)
            c.drawCentredString(width/2, height - 5*inch, certificate.course.title)
            
            c.setFont('Helvetica', 12)
            completion_date = certificate.issued_date.strftime("%B %d, %Y")
            c.drawCentredString(width/2, height - 6*inch, f"Completed on: {completion_date}")
            c.drawCentredString(width/2, height - 6.5*inch, f"Verification Code: {certificate.verification_code}")
            
            c.showPage()
            c.save()
            
            pdf_content = buffer.getvalue()
            buffer.close()
            
            filename = f"certificate_{certificate.verification_code}.pdf"
            filepath = f"certificates/{filename}"
            
            certificate.certificate_file.save(filename, ContentFile(pdf_content), save=False)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error in fallback certificate generation: {e}")
            # Return a path anyway, the file will be generated on access
            return f"certificates/certificate_{certificate.verification_code}.pdf"





class CertificateDownloadView2(APIView):
    """Download certificate PDF file with force download option"""
    permission_classes = [IsStudent]
    
    def get(self, request, certificate_id):
        try:
            certificate = StudentCertificate.objects.get(
                id=certificate_id, 
                student=request.user
            )
            
            if not certificate.certificate_file:
                return Response(
                    {'error': 'Certificate not generated yet'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if file exists
            # if not os.path.exists(certificate.certificate_file.path):
            #     return Response(
            #         {'error': 'Certificate file not found on server'},
            #         status=status.HTTP_404_NOT_FOUND
            #     )
            
            # Read file content
            try:
                with open(certificate.certificate_file.path, 'rb') as f:
                    file_content = f.read()
            except Exception as e:
                logger.error(f"Error reading certificate file: {e}")
                return Response(
                    {'error': 'Error reading certificate file'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Check if user wants to force download (via query parameter)
            force_download = request.GET.get('download', 'false').lower() == 'true'
            
            response = HttpResponse(file_content, content_type='application/pdf')
            filename = f"certificate_{certificate.verification_code}.pdf"
            
            if force_download:
                # Force download
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
            else:
                # Let browser decide (may open in preview)
                response['Content-Disposition'] = f'inline; filename="{filename}"'
            
            response['Content-Length'] = len(file_content)
            
            return response
            
        except StudentCertificate.DoesNotExist:
            return Response(
                {'error': 'Certificate not found'},
                status=status.HTTP_404_NOT_FOUND
            )



# import os
# import uuid
# import logging
# from io import BytesIO
# from django.shortcuts import get_object_or_404
# from django.http import HttpResponse
# from django.utils import timezone
# from django.conf import settings
# from django.core.files.base import ContentFile
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from reportlab.pdfgen import canvas
# from reportlab.lib.pagesizes import letter
# from reportlab.lib.colors import HexColor
# from reportlab.lib.units import inch
# from reportlab.pdfmetrics import registerFont
# from reportlab.pdfbase.ttfonts import TTFont
# from reportlab.lib.utils import ImageReader
# import cloudinary
# import cloudinary.uploader
# import requests

logger = logging.getLogger(__name__)

class CertificateView(APIView):
    """Get certificate for a completed course"""
    permission_classes = [IsStudent]
    
    def get(self, request, course_id):
        try:
            student = request.user
            course = get_object_or_404(Course, id=course_id)
            
            # Check if student has completed the course
            enrollment = get_object_or_404(
                Enrollment,
                student=student,
                course=course,
                is_active=True
            )
            
            if enrollment.progress_percentage < 100:
                return Response(
                    {
                        'error': 'Course not completed yet',
                        'progress': float(enrollment.progress_percentage),
                        'required': 100.0
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get or create certificate
            certificate, created = StudentCertificate.objects.get_or_create(
                student=student,
                course=course,
                defaults={
                    'verification_code': self.generate_verification_code(),
                    'issued_date': timezone.now()
                }
            )
            
            # Generate PDF certificate if not exists or needs regeneration
            if not certificate.certificate_file or self.needs_regeneration(certificate):
                try:
                    cloudinary_url = self.generate_and_upload_certificate_pdf(certificate)
                    if cloudinary_url:
                        certificate.certificate_file = cloudinary_url
                        certificate.save()
                    else:
                        return Response(
                            {'error': 'Failed to generate or upload certificate. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                except Exception as e:
                    logger.error(f"Certificate generation failed: {e}")
                    return Response(
                        {'error': 'Failed to generate certificate. Please try again later.'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Check if certificate file URL exists
            if not certificate.certificate_file:
                return Response(
                    {'error': 'Certificate file not available'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response({
                'certificate_url': certificate.certificate_file,
                'download_url': f"/api/student/certificates/download/{certificate.id}/",
                'verification_code': certificate.verification_code,
                'issued_date': certificate.issued_date,
                'student_name': student.full_name,
                'course_title': course.title,
                'message': 'Certificate generated successfully' if created else 'Certificate retrieved successfully'
            })
            
        except Exception as e:
            logger.error(f"Certificate view error: {e}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def generate_verification_code(self):
        """Generate a unique verification code for certificates"""
        return str(uuid.uuid4()).replace('-', '')[:16].upper()
    
    def needs_regeneration(self, certificate):
        """Check if certificate needs to be regenerated"""
        # Regenerate if file doesn't exist or URL is invalid
        if not certificate.certificate_file:
            return True
        
        # Check if Cloudinary URL is still valid (optional - may increase response time)
        try:
            response = requests.head(certificate.certificate_file, timeout=5)
            if response.status_code != 200:
                return True
        except:
            return True
        
        # Regenerate if issued date changed significantly (optional business logic)
        if certificate.issued_date and (timezone.now() - certificate.issued_date).days > 365:
            return True
            
        return False
    
    def generate_and_upload_certificate_pdf(self, certificate):
        """Generate PDF certificate and upload to Cloudinary"""
        try:
            # Generate PDF content
            pdf_content = self.generate_certificate_pdf(certificate)
            
            if pdf_content:
                # Upload to Cloudinary
                filename = f"certificate_{certificate.verification_code}"
                
                upload_result = cloudinary.uploader.upload(
                    pdf_content,
                    resource_type="raw",  # For non-image files like PDFs
                    public_id=f"certificates/{filename}",
                    format="pdf",
                    use_filename=True,
                    unique_filename=False,
                    overwrite=True
                )
                
                return upload_result.get('secure_url')
            
            return None
            
        except Exception as e:
            logger.error(f"Error uploading certificate to Cloudinary: {e}")
            return None
    
    def generate_certificate_pdf(self, certificate):
        """Generate PDF certificate using ReportLab"""
        try:
            # Create a buffer for the PDF
            buffer = BytesIO()
            
            # Create the PDF object
            c = canvas.Canvas(buffer, pagesize=letter)
            width, height = letter
            
            # Register fonts (fallback to standard fonts if custom fonts aren't available)
            try:
                font_path = os.path.join(settings.BASE_DIR, 'static', 'fonts')
                
                if os.path.exists(os.path.join(font_path, 'OpenSans-Bold.ttf')):
                    registerFont(TTFont('OpenSans-Bold', os.path.join(font_path, 'OpenSans-Bold.ttf')))
                if os.path.exists(os.path.join(font_path, 'OpenSans-Regular.ttf')):
                    registerFont(TTFont('OpenSans-Regular', os.path.join(font_path, 'OpenSans-Regular.ttf')))
            except:
                pass  # Use standard fonts if custom fonts aren't available
            
            # Add background design or border
            self.draw_certificate_design(c, width, height)
            
            # Add certificate title
            c.setFillColor(HexColor('#2C3E50'))  # Dark blue
            c.setFont('Helvetica-Bold', 36)
            c.drawCentredString(width/2, height - 2*inch, "CERTIFICATE OF COMPLETION")
            
            # Add decorative line
            c.setStrokeColor(HexColor('#3498DB'))
            c.setLineWidth(2)
            c.line(width/2 - 2*inch, height - 2.3*inch, width/2 + 2*inch, height - 2.3*inch)
            
            # Add "This is to certify that"
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 18)
            c.drawCentredString(width/2, height - 3*inch, "This is to certify that")
            
            # Add student name
            c.setFillColor(HexColor('#2C3E50'))
            c.setFont('Helvetica-Bold', 28)
            student_name = certificate.student.full_name.upper()
            c.drawCentredString(width/2, height - 3.8*inch, student_name)
            
            # Add "has successfully completed the course"
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 18)
            c.drawCentredString(width/2, height - 4.6*inch, f"has successfully completed the course {certificate.course.title}")
            
            # Add course title
            c.setFillColor(HexColor('#E74C3C'))
            c.setFont('Helvetica-Bold', 22)
            course_title = certificate.course.title
            # Wrap text if too long
            if len(course_title) > 40:
                lines = self.wrap_text(course_title, 40)
                for i, line in enumerate(lines):
                    c.drawCentredString(width/2, height - (5.2 + i*0.4)*inch, line)
            else:
                c.drawCentredString(width/2, height - 5.2*inch, course_title)
            
            # Add completion date
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 14)
            completion_date = certificate.issued_date.strftime("%B %d, %Y")
            c.drawCentredString(width/2, height - 6.2*inch, f"Completed on: {completion_date}")
            
            # Add verification code
            c.setFillColor(HexColor('#95A5A6'))
            c.setFont('Helvetica-Oblique', 12)
            c.drawCentredString(width/2, height - 6.8*inch, f"Verification Code: {certificate.verification_code}")
            
            # Add platform URL
            c.setFillColor(HexColor('#BDC3C7'))
            c.setFont('Helvetica', 10)
            c.drawCentredString(width/2, 0.5*inch, "Verify at: https://yourplatform.com/verify-certificate/")
            
            # Add signatures area
            self.draw_signatures(c, width, height)
            
            # Save the PDF
            c.showPage()
            c.save()
            
            # Get PDF content from buffer
            pdf_content = buffer.getvalue()
            buffer.close()
            
            return pdf_content
            
        except Exception as e:
            logger.error(f"Error generating certificate PDF: {e}")
            # Try fallback simple certificate
            return self.generate_simple_certificate(certificate)
    
    def draw_certificate_design(self, c, width, height):
        """Draw certificate background design"""
        # Add decorative border
        c.setStrokeColor(HexColor('#3498DB'))
        c.setLineWidth(3)
        c.rect(0.5*inch, 0.5*inch, width - 1*inch, height - 1*inch)
        
        # Add decorative corners
        corner_size = 0.3*inch
        corners = [
            (0.5*inch, 0.5*inch),  # bottom-left
            (0.5*inch, height - 0.5*inch),  # top-left
            (width - 0.5*inch, 0.5*inch),  # bottom-right
            (width - 0.5*inch, height - 0.5*inch)  # top-right
        ]
        
        for x, y in corners:
            c.setLineWidth(2)
            c.line(x, y, x + corner_size, y)
            c.line(x, y, x, y + corner_size)
        
        # Add watermark (optional - from Cloudinary or local file)
        try:
            watermark_path = os.path.join(settings.BASE_DIR, 'static', 'images', 'watermark.png')
            if os.path.exists(watermark_path):
                watermark = ImageReader(watermark_path)
                c.drawImage(watermark, width/2 - 1*inch, height/2 - 1*inch, 
                           width=2*inch, height=2*inch, mask='auto')
        except:
            pass
    
    def draw_signatures(self, c, width, height):
        """Draw signature lines"""
        # Instructor signature
        c.setStrokeColor(HexColor('#7F8C8D'))
        c.setLineWidth(1)
        c.line(width/4 - 1.5*inch, 1.5*inch, width/4 + 1.5*inch, 1.5*inch)
        c.setFillColor(HexColor('#7F8C8D'))
        c.setFont('Helvetica', 12)
        c.drawCentredString(width/4, 1.2*inch, "Instructor Signature")
        
        # Platform signature
        c.line(3*width/4 - 1.5*inch, 1.5*inch, 3*width/4 + 1.5*inch, 1.5*inch)
        c.drawCentredString(3*width/4, 1.2*inch, "Platform Seal")
    
    def wrap_text(self, text, max_length):
        """Wrap text into multiple lines if too long"""
        words = text.split()
        lines = []
        current_line = []
        
        for word in words:
            if len(' '.join(current_line + [word])) <= max_length:
                current_line.append(word)
            else:
                lines.append(' '.join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
    def generate_simple_certificate(self, certificate):
        """Fallback function for simple certificate generation"""
        try:
            buffer = BytesIO()
            c = canvas.Canvas(buffer, pagesize=letter)
            width, height = letter
            
            # Simple certificate design
            c.setFont('Helvetica-Bold', 24)
            c.drawCentredString(width/2, height - 3*inch, "CERTIFICATE OF COMPLETION")
            
            c.setFont('Helvetica', 16)
            c.drawCentredString(width/2, height - 3*inch, "This certifies that")
            
            c.setFont('Helvetica-Bold', 20)
            c.drawCentredString(width/2, height - 3.5*inch, certificate.student.full_name.upper())
            
            c.setFont('Helvetica', 16)
            c.drawCentredString(width/2, height - 4.5*inch, "has successfully completed")
            
            # c.setFont('Helvetica-Bold', 18)
            # c.drawCentredString(width/2, height - 5*inch, certificate.course.title)
            
            c.setFont('Helvetica', 12)
            completion_date = certificate.issued_date.strftime("%B %d, %Y")
            c.drawCentredString(width/2, height - 6*inch, f"Completed on: {completion_date}")
            c.drawCentredString(width/2, height - 6.5*inch, f"Verification Code: {certificate.verification_code}")
            
            c.showPage()
            c.save()
            
            pdf_content = buffer.getvalue()
            buffer.close()
            
            return pdf_content
            
        except Exception as e:
            logger.error(f"Error in fallback certificate generation: {e}")
            return None


class CertificateDownloadView(APIView):
    """Download certificate PDF file with force download option"""
    permission_classes = [IsStudent]
    
    def get(self, request, certificate_id):
        try:
            certificate = StudentCertificate.objects.get(
                id=certificate_id,
                student=request.user
            )
            
            if not certificate.certificate_file:
                return Response(
                    {'error': 'Certificate not generated yet'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Download file content from Cloudinary URL
            try:
                response = requests.get(certificate.certificate_file, timeout=30)
                response.raise_for_status()  # Raises an HTTPError for bad responses
                file_content = response.content
            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading certificate from Cloudinary: {e}")
                return Response(
                    {'error': 'Error downloading certificate file'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            except Exception as e:
                logger.error(f"Unexpected error downloading certificate: {e}")
                return Response(
                    {'error': 'Error reading certificate file'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Check if user wants to force download (via query parameter)
            force_download = request.GET.get('download', 'false').lower() == 'true'
            
            response = HttpResponse(file_content, content_type='application/pdf')
            filename = f"certificate_{certificate.verification_code}.pdf"
            
            if force_download:
                # Force download
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
            else:
                # Let browser decide (may open in preview)
                response['Content-Disposition'] = f'inline; filename="{filename}"'
            
            response['Content-Length'] = len(file_content)
            return response
            
        except StudentCertificate.DoesNotExist:
            return Response(
                {'error': 'Certificate not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Certificate download error: {e}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class EnrollmentListView(generics.ListAPIView):
    """List all enrollments with progress for the student"""
    permission_classes = [IsStudent]
    serializer_class = EnrollmentWithProgressSerializer
    
    def get_queryset(self):
        student = self.request.user
        
        # Get enrollments with related data
        enrollments = Enrollment.objects.filter(
            student=student,
            is_active=True
        ).select_related('course').prefetch_related(
            Prefetch('course__sections'),
            Prefetch('course__reviews')
        )
        
        # Annotate with last activity
        for enrollment in enrollments:
            # Get last section view
            last_section_view = SectionView.objects.filter(
                student=student,
                section__course=enrollment.course
            ).aggregate(last_viewed=Max('last_viewed_at'))['last_viewed']
            
            # Get last quiz attempt
            last_quiz_attempt = QuizAttempt.objects.filter(
                student=student,
                quiz__section__course=enrollment.course
            ).aggregate(last_attempt=Max('started_at'))['last_attempt']
            
            # Determine the most recent activity
            last_activity = None
            if last_section_view and last_quiz_attempt:
                last_activity = max(last_section_view, last_quiz_attempt)
            elif last_section_view:
                last_activity = last_section_view
            elif last_quiz_attempt:
                last_activity = last_quiz_attempt
                
            # Add to enrollment object
            enrollment.last_activity = last_activity
        
        return enrollments

class CourseRecommendationsView(APIView):
    """Get course recommendations based on student's interests and progress"""
    permission_classes = [IsStudent]
    
    def get(self, request):
        student = request.user
        
        # Get student's enrolled courses
        enrolled_courses = Course.objects.filter(
            enrollments__student=student,
            enrollments__is_active=True
        )
        
        # Get categories of enrolled courses
        # This assumes you have a category field in your Course model
        # If not, you might need to adjust this logic
        enrolled_categories = enrolled_courses.values_list('category', flat=True).distinct()
        
        # Recommend courses in same categories but not enrolled
        recommended_courses = Course.objects.filter(
            status='published'
        ).exclude(
            enrollments__student=student,
            enrollments__is_active=True
        )
        
        if enrolled_categories:
            recommended_courses = recommended_courses.filter(
                category__in=enrolled_categories
            )
        
        # Add popular courses if not enough recommendations
        if recommended_courses.count() < 5:
            popular_courses = Course.objects.filter(
                status='published'
            ).exclude(
                enrollments__student=student,
                enrollments__is_active=True
            ).order_by('-total_enrollments')[:10]
            
            recommended_courses = list(recommended_courses) + list(popular_courses)
        
        serializer = CourseListSerializer(recommended_courses[:10], many=True)
        return Response(serializer.data)

class LearningStatisticsView(APIView):
    """Get learning statistics for the student"""
    permission_classes = [IsStudent]
    
    def get(self, request):
        student = request.user
        
        # Get total time spent learning
        total_time = SectionView.objects.filter(
            student=student
        ).aggregate(total_time=Sum('total_time_spent_minutes'))['total_time'] or 0
        
        # Get courses in progress
        in_progress = Enrollment.objects.filter(
            student=student,
            is_active=True,
            progress_percentage__lt=100
        ).count()
        
        # Get completed courses
        completed = Enrollment.objects.filter(
            student=student,
            is_active=True,
            progress_percentage=100
        ).count()
        
        # Get daily streak (consecutive days with learning activity)
        today = timezone.now().date()
        streak = 0
        current_date = today
        
        while True:
            had_activity = SectionView.objects.filter(
                student=student,
                last_viewed_at__date=current_date
            ).exists() or QuizAttempt.objects.filter(
                student=student,
                started_at__date=current_date
            ).exists()
            
            if had_activity:
                streak += 1
                current_date -= timedelta(days=1)
            else:
                break
        
        return Response({
            'total_learning_time_minutes': total_time,
            'courses_in_progress': in_progress,
            'courses_completed': completed,
            'current_streak_days': streak,
            'total_quizzes_taken': QuizAttempt.objects.filter(student=student).count(),
            'average_quiz_score': QuizAttempt.objects.filter(
                student=student,
                is_completed=True
            ).aggregate(avg_score=Avg('score'))['avg_score'] or 0
        })
        
# student/views.py (enhanced version)
class TemporaryEnrollmentView(APIView):
    """Temporarily enroll student in a course without payment"""
    permission_classes = [IsStudent]
    
    def post(self, request, course_id):
        student = request.user
        
        # Validate course exists
        serializer = TemporaryEnrollmentSerializer(data={'course_id': course_id})
        if not serializer.is_valid():
            return Response(
                {'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        course = Course.objects.get(id=course_id)
        
        # Check if student is already enrolled
        if Enrollment.objects.filter(
            student=student,
            course=course,
            is_active=True
        ).exists():
            return Response(
                {'error': 'Already enrolled in this course'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create enrollment without payment
        enrollment = Enrollment.objects.create(
            student=student,
            course=course,
            is_active=True,
            progress_percentage=0.00
        )
        
        # Update course enrollment count
        course.total_enrollments = course.enrollments.filter(is_active=True).count()
        course.save(update_fields=['total_enrollments'])
        
        return Response({
            'message': 'Successfully enrolled in course',
            'enrollment_id': enrollment.id,
            'course': {
                'id': course.id,
                'title': course.title,
                'teacher': course.teacher.full_name
            },
            'enrolled_at': enrollment.enrolled_at
        }, status=status.HTTP_201_CREATED)

class BulkTemporaryEnrollmentView(APIView):
    """Temporarily enroll student in multiple courses without payment"""
    permission_classes = [IsStudent]
    
    def post(self, request):
        student = request.user
        
        serializer = BulkTemporaryEnrollmentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        course_ids = serializer.validated_data['course_ids']
        enrolled_courses = []
        already_enrolled = []
        
        for course_id in course_ids:
            course = Course.objects.get(id=course_id)
            
            # Check if already enrolled
            if Enrollment.objects.filter(
                student=student,
                course=course,
                is_active=True
            ).exists():
                already_enrolled.append({
                    'course_id': course.id,
                    'course_title': course.title
                })
                continue
            
            # Create enrollment
            enrollment = Enrollment.objects.create(
                student=student,
                course=course,
                is_active=True,
                progress_percentage=0.00
            )
            
            enrolled_courses.append({
                'course_id': course.id,
                'course_title': course.title,
                'enrollment_id': enrollment.id,
                'teacher': course.teacher.full_name
            })
        
        # Update enrollment counts for all affected courses
        for course in Course.objects.filter(id__in=course_ids):
            course.total_enrollments = course.enrollments.filter(is_active=True).count()
            course.save(update_fields=['total_enrollments'])
        
        return Response({
            'success': True,
            'enrolled_courses': enrolled_courses,
            'already_enrolled': already_enrolled,
            'summary': {
                'total_requested': len(course_ids),
                'successfully_enrolled': len(enrolled_courses),
                'already_enrolled': len(already_enrolled)
            }
        }, status=status.HTTP_201_CREATED)
        
# student/views.py
class AdminEnrollmentView(APIView):
    """Admin API to enroll any student in any course without payment"""
    permission_classes = [permissions.IsAdminUser]
    
    def post(self, request):
        student_id = request.data.get('student_id')
        course_id = request.data.get('course_id')
        
        if not student_id or not course_id:
            return Response(
                {'error': 'Both student_id and course_id are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            student = User.objects.get(id=student_id, user_type='student')
            course = Course.objects.get(id=course_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'Student not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Course.DoesNotExist:
            return Response(
                {'error': 'Course not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if already enrolled
        if Enrollment.objects.filter(
            student=student,
            course=course,
            is_active=True
        ).exists():
            return Response(
                {'error': 'Student is already enrolled in this course'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create enrollment
        enrollment = Enrollment.objects.create(
            student=student,
            course=course,
            is_active=True,
            progress_percentage=0.00
        )
        
        # Update course enrollment count
        course.total_enrollments = course.enrollments.filter(is_active=True).count()
        course.save(update_fields=['total_enrollments'])
        
        return Response({
            'message': 'Student successfully enrolled in course',
            'enrollment_id': enrollment.id,
            'student': {
                'id': student.id,
                'name': student.full_name,
                'email': student.email
            },
            'course': {
                'id': course.id,
                'title': course.title,
                'teacher': course.teacher.full_name
            }
        }, status=status.HTTP_201_CREATED)
        
        
        
# student/views.py
from django.http import FileResponse, Http404
from django.utils.text import slugify
import os

import logging
logger = logging.getLogger(__name__)



from rest_framework.throttling import UserRateThrottle

class PDFDownloadThrottle(UserRateThrottle):
    rate = '10/minute'  # 10 downloads per minute per user

# student/views.py (enhanced)
class SectionPDFDownloadView(APIView):
    """Download PDF file from a section with enhanced security"""
    permission_classes = [IsStudent]
    throttle_classes = [PDFDownloadThrottle]
    
    def get(self, request, section_id):
        try:
            student = request.user
            section = Section.objects.get(id=section_id)
            
            # Check enrollment
            if not Enrollment.objects.filter(
                student=student,
                course=section.course,
                is_active=True
            ).exists():
                return Response(
                    {'error': 'Not enrolled in this course'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            return self.serve_pdf_file(section)
            
        except Section.DoesNotExist:
            return Response(
                {'error': 'Section not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"PDF download error: {e}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def serve_pdf_file(self, section):
        """Helper method to serve PDF file"""
        if not section.pdf_file:
            raise Http404("No PDF file available")
        
        if not os.path.exists(section.pdf_file.path):
            raise Http404("PDF file not found on server")
        
        # Generate safe filename
        filename = self.generate_safe_filename(section)
        
        # Open and serve file
        file_handle = section.pdf_file.open('rb')
        response = FileResponse(file_handle, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Content-Length'] = section.pdf_file.size
        
        return response
    
    def generate_safe_filename(self, section):
        """Generate a safe filename for download"""
        course_name = slugify(section.course.title)[:50]
        section_name = slugify(section.title)[:50]
        return f"{course_name}_section_{section.order}_{section_name}.pdf"


         
class CourseAllPDFsDownloadView(APIView):
    """Get download links for all PDFs in a course"""
    permission_classes = [IsStudent]
    
    def get(self, request, course_id):
        student = request.user
        course = get_object_or_404(Course, id=course_id)
        
        # Check if student is enrolled in the course
        enrollment = get_object_or_404(
            Enrollment, 
            student=student, 
            course=course,
            is_active=True
        )
        
        # Get all sections with PDF files
        sections_with_pdf = course.sections.filter(
            pdf_file__isnull=False
        ).exclude(pdf_file='')
        
        pdf_files = []
        
        for section in sections_with_pdf:
            if os.path.exists(section.pdf_file.path):
                pdf_files.append({
                    'section_id': section.id,
                    'section_title': section.title,
                    'section_order': section.order,
                    'pdf_filename': os.path.basename(section.pdf_file.name),
                    'pdf_size': section.pdf_file.size,
                    'download_url': f"/api/student/sections/{section.id}/download-pdf/",
                    'uploaded_at': section.updated_at
                })
        
        return Response({
            'course_id': course.id,
            'course_title': course.title,
            'total_pdfs': len(pdf_files),
            'pdf_files': pdf_files
        })

# views.py
from rest_framework import generics, filters
from rest_framework.permissions import IsAuthenticated
from teacher.models import Notification
from teacher.serializers import NotificationSerializer
from account.permissions import IsStudent


class StudentNotificationsView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsStudent]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['created_at', 'is_read']
    ordering = ['-created_at']
    
    def get_queryset(self):
        return Notification.objects.filter(
            recipients=self.request.user
        ).select_related('sender', 'course')
    
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        
        # Always return 200 with empty array if no notifications
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response({
                'notifications': serializer.data,
                'unread_count': queryset.filter(is_read=False).count(),
                'total_count': queryset.count()
            })
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'notifications': serializer.data,
            'unread_count': queryset.filter(is_read=False).count(),
            'total_count': queryset.count()
        })
class MarkNotificationAsReadView(generics.UpdateAPIView):
    permission_classes = [IsStudent]
    
    def update(self, request, *args, **kwargs):
        notification = generics.get_object_or_404(
            Notification, 
            id=kwargs['pk'], 
            recipients=request.user
        )
        
        
        if notification.is_read:
            return Response({
                'message': 'Notification already marked as read'
            })
        
        notification.is_read = True
        notification.save()
        
        
        
        return Response({
            'status': 'success',
            'message': 'Notification marked as read'
        })