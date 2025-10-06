import traceback
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
logger = logging.getLogger(__name__)


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


class CertificateView(APIView):
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
            certificate, created = StudentCertificate.objects.select_related('student', 'course').get_or_create(
                student=student,
                course=course,
                defaults={
                    'verification_code': self.generate_verification_code(),
                    'issued_date': timezone.now()
                }
            )
            
            # If certificate already exists, ensure relationships are loaded
            if not created:
                certificate = StudentCertificate.objects.select_related('student', 'course').get(id=certificate.id)
            
            # Generate PDF certificate if not exists or needs regeneration
            if not certificate.certificate_file or self.needs_regeneration(certificate):
                try:
                    cloudinary_url = self.generate_and_upload_certificate_pdf(certificate)
                    if cloudinary_url:
                        certificate.certificate_file = cloudinary_url
                        certificate.save()
                    else:
                        logger.error("Failed to generate or upload certificate - no URL returned")
                        return Response(
                            {'error': 'Failed to generate or upload certificate. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                except Exception as e:
                    logger.error(f"Certificate generation failed with exception: {str(e)}", exc_info=True)
                    return Response(
                        {'error': f'Failed to generate certificate: {str(e)}'},
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
            {
                'error': 'failed to retrieve certificate',
                'details': str(e),
                'traceback': traceback.format_exc()
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    def generate_verification_code(self):
        """Generate a unique verification code for certificates"""
        return str(uuid.uuid4()).replace('-', '')[:16].upper()
    
    def needs_regeneration(self, certificate):
        """Check if certificate needs to be regenerated"""
        if not certificate.certificate_file:
            return True
        
        try:
            response = requests.head(certificate.certificate_file, timeout=5)
            if response.status_code != 200:
                return True
        except:
            return True
        
        if certificate.issued_date and (timezone.now() - certificate.issued_date).days > 365:
            return True
            
        return False
    
    def generate_and_upload_certificate_pdf(self, certificate):
        """Generate PDF certificate and upload to Cloudinary"""
        try:
            logger.info(f"Starting certificate generation for verification code: {certificate.verification_code}")
            
            pdf_content = self.generate_certificate_pdf(certificate)
            
            if not pdf_content:
                logger.error("PDF generation returned None or empty content")
                return None
            
            logger.info(f"PDF generated successfully, size: {len(pdf_content)} bytes")
            
            filename = f"certificate_{certificate.verification_code}"
            
            logger.info(f"Uploading to Cloudinary with filename: {filename}")
            
            upload_result = cloudinary.uploader.upload(
                pdf_content,
                resource_type="raw",
                public_id=f"certificates/{filename}",
                format="pdf",
                use_filename=True,
                unique_filename=False,
                overwrite=True
            )
            
            secure_url = upload_result.get('secure_url')
            logger.info(f"Upload successful, URL: {secure_url}")
            
            return secure_url
            
        except cloudinary.exceptions.Error as e:
            logger.error(f"Cloudinary upload error: {str(e)}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error uploading certificate to Cloudinary: {str(e)}", exc_info=True)
            return None
    
    def get_display_text(self, certificate):
        """Get display text for certificate - returns original text without transliteration"""
        course = certificate.course
        student = certificate.student
        
        # Use course title as is (Arabic or English)
        course_title = course.title
        logger.info(f"Using course title as is: {course_title}")
        
        # Use student name as is (Arabic or English)
        if hasattr(student, 'full_name') and student.full_name:
            student_name = student.full_name
        elif hasattr(student, 'first_name') and hasattr(student, 'last_name'):
            student_name = f"{student.first_name} {student.last_name}".strip()
        else:
            student_name = str(student)
        
        logger.info(f"Student name: {student_name}, Course title: {course_title}")
        return student_name, course_title
    
   
    
    def generate_certificate_pdf(self, certificate):
        """Generate PDF certificate with proper Arabic font support"""
        try:
            # Get display text as is
            student_name, course_title = self.get_display_text(certificate)
            
            logger.info(f"Certificate text - Student: '{student_name}', Course: '{course_title}'")
            
            # Import required libraries
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.pdfgen import canvas
            from io import BytesIO
            import arabic_reshaper
            from bidi.algorithm import get_display
            import os
            
            # Create PDF buffer
            buffer = BytesIO()
            
            # Use A4 for better international compatibility
            c = canvas.Canvas(buffer, pagesize=A4)
            width, height = A4
            
            # Register fonts that support Arabic
            self.register_arabic_fonts(c)
            
            # Process Arabic text
            def prepare_arabic_text(text):
                """Process Arabic text for proper display"""
                if self.contains_arabic(text):
                    try:
                        # Configure reshaper for better Arabic rendering
                        reshaper_config = arabic_reshaper.config_for_true_type_font(
                            'fonts/DejaVuSans.ttf',  # or your font path
                            arabic_reshaper.ENABLE_ALL_FEATURES
                        )
                        arabic_reshaper.config = reshaper_config
                        
                        reshaped_text = arabic_reshaper.reshape(text)
                        return get_display(reshaped_text)
                    except Exception as e:
                        logger.warning(f"Arabic processing failed: {e}, using original text")
                        return text
                return text
            
            # Prepare texts
            display_student_name = prepare_arabic_text(student_name)
            display_course_title = prepare_arabic_text(course_title)
            
            # Set the font based on text content
            student_font = "ArabicFont" if self.contains_arabic(student_name) else "Helvetica-Bold"
            course_font = "ArabicFont" if self.contains_arabic(course_title) else "Helvetica-Bold"
            
            # Certificate design
            self.draw_certificate_design(c, width, height)
            
            # Certificate title (English)
            c.setFillColor(HexColor('#2C3E50'))
            c.setFont('Helvetica-Bold', 30)
            c.drawCentredString(width/2, height - 2*inch, "CERTIFICATE OF COMPLETION")
            
            # "This is to certify that"
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 18)
            c.drawCentredString(width/2, height - 3*inch, "This is to certify that")
            
            # Student name
            c.setFillColor(HexColor('#2C3E50'))
            c.setFont(student_font, 28 if student_font == "Helvetica-Bold" else 24)
            
            if self.contains_arabic(student_name):
                # For Arabic text, use custom positioning
                text_width = c.stringWidth(display_student_name, "ArabicFont", 24)
                c.drawString((width - text_width) / 2, height - 3.8*inch, display_student_name)
            else:
                c.drawCentredString(width/2, height - 3.8*inch, display_student_name.upper())
            
            # "has successfully completed the course"
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 18)
            c.drawCentredString(width/2, height - 4.6*inch, "has successfully completed the course")
            
            # Course title
            c.setFillColor(HexColor('#E74C3C'))
            c.setFont(course_font, 22 if course_font == "Helvetica-Bold" else 18)
            
            if self.contains_arabic(course_title):
                # Handle Arabic course title
                if len(course_title) > 25:
                    lines = self.wrap_arabic_text(course_title, 25)
                    y_position = height - 5.2*inch
                    for line in lines[:3]:
                        display_line = prepare_arabic_text(line)
                        text_width = c.stringWidth(display_line, "ArabicFont", 18)
                        c.drawString((width - text_width) / 2, y_position, display_line)
                        y_position -= 0.4*inch
                else:
                    text_width = c.stringWidth(display_course_title, "ArabicFont", 18)
                    c.drawString((width - text_width) / 2, height - 5.2*inch, display_course_title)
            else:
                # Handle English course title
                if len(course_title) > 50:
                    lines = self.wrap_text(course_title, 50)
                    y_position = height - 5.2*inch
                    for line in lines[:3]:
                        c.drawCentredString(width/2, y_position, line)
                        y_position -= 0.4*inch
                else:
                    c.drawCentredString(width/2, height - 5.2*inch, course_title)
            
            # Completion date
            c.setFillColor(HexColor('#7F8C8D'))
            c.setFont('Helvetica', 14)
            completion_date = certificate.issued_date.strftime("%B %d, %Y")
            c.drawCentredString(width/2, height - 6.5*inch, f"Completed on: {completion_date}")
            
            # Verification code
            c.setFillColor(HexColor('#95A5A6'))
            c.setFont('Helvetica-Oblique', 12)
            c.drawCentredString(width/2, height - 7*inch, f"Verification Code: {certificate.verification_code}")
            
            # Signature lines
            self.draw_signature_lines(c, width, height)
            
            # Save PDF
            c.showPage()
            c.save()
            
            pdf_content = buffer.getvalue()
            buffer.close()
            
            logger.info("✅ PDF generated successfully with Arabic support")
            return pdf_content
            
        except Exception as e:
            logger.error(f"Error generating certificate PDF: {e}", exc_info=True)
            import traceback
            logger.error(traceback.format_exc())
            return None
    
    def register_arabic_fonts(self, canvas):
        """Register fonts that support Arabic characters"""
        try:
            # Try different font paths - DejaVu fonts are good for Arabic
            font_paths = [
                # Common system paths for DejaVu fonts
                '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
                '/System/Library/Fonts/Arial.ttf',
                'C:/Windows/Fonts/arial.ttf',
                'C:/Windows/Fonts/tahoma.ttf',
                # You can also download and include fonts in your project
                'static/fonts/DejaVuSans.ttf',
                'media/fonts/DejaVuSans.ttf',
            ]
            
            # Also try to use reportlab's built-in font search
            from reportlab.lib.fonts import addMapping
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            
            arabic_font_registered = False
            
            for font_path in font_paths:
                try:
                    if os.path.exists(font_path):
                        pdfmetrics.registerFont(TTFont('ArabicFont', font_path))
                        # Also register bold variant if available
                        bold_path = font_path.replace('.ttf', '-Bold.ttf')
                        if os.path.exists(bold_path):
                            pdfmetrics.registerFont(TTFont('ArabicFont-Bold', bold_path))
                        logger.info(f"✅ Successfully registered Arabic font: {font_path}")
                        arabic_font_registered = True
                        break
                except Exception as e:
                    logger.warning(f"Could not register font {font_path}: {e}")
                    continue
            
            if not arabic_font_registered:
                logger.warning("❌ No Arabic font found, Arabic text may not display correctly")
                # Fallback: use Helvetica (will show boxes for Arabic)
                pdfmetrics.registerFont(TTFont('ArabicFont', 'Helvetica'))
                
        except Exception as e:
            logger.error(f"Font registration error: {e}")
    
    def draw_certificate_design(self, canvas, width, height):
        """Draw certificate decorative elements"""
        # Decorative border
        canvas.setStrokeColor(HexColor('#3498DB'))
        canvas.setLineWidth(3)
        canvas.rect(0.5*inch, 0.5*inch, width - 1*inch, height - 1*inch)
        
        # Decorative corners
        corner_size = 0.3*inch
        corners = [
            (0.5*inch, 0.5*inch),
            (0.5*inch, height - 0.5*inch),
            (width - 0.5*inch, 0.5*inch),
            (width - 0.5*inch, height - 0.5*inch)
        ]
        
        for x, y in corners:
            canvas.setLineWidth(2)
            canvas.line(x, y, x + corner_size, y)
            canvas.line(x, y, x, y + corner_size)
        
        # Decorative line under title
        canvas.setStrokeColor(HexColor('#3498DB'))
        canvas.setLineWidth(2)
        canvas.line(width/2 - 2*inch, height - 2.3*inch, width/2 + 2*inch, height - 2.3*inch)
    
    def draw_signature_lines(self, canvas, width, height):
        """Draw signature lines"""
        canvas.setStrokeColor(HexColor('#7F8C8D'))
        canvas.setLineWidth(1)
        canvas.line(width/4 - 1.5*inch, 1.5*inch, width/4 + 1.5*inch, 1.5*inch)
        canvas.setFillColor(HexColor('#7F8C8D'))
        canvas.setFont('Helvetica', 12)
        canvas.drawCentredString(width/4, 1.2*inch, "Instructor Signature")
        
        canvas.line(3*width/4 - 1.5*inch, 1.5*inch, 3*width/4 + 1.5*inch, 1.5*inch)
        canvas.drawCentredString(3*width/4, 1.2*inch, "Platform Seal")
    
    def contains_arabic(self, text):
        """Check if text contains Arabic characters"""
        if not text:
            return False
        
        # Arabic Unicode ranges
        arabic_ranges = [
            (0x0600, 0x06FF),  # Arabic
            (0x0750, 0x077F),  # Arabic Supplement
            (0x08A0, 0x08FF),  # Arabic Extended-A
            (0xFB50, 0xFDFF),  # Arabic Presentation Forms-A
            (0xFE70, 0xFEFF),  # Arabic Presentation Forms-B
        ]
        
        for char in str(text):
            char_code = ord(char)
            for start, end in arabic_ranges:
                if start <= char_code <= end:
                    return True
        return False
    
    def wrap_arabic_text(self, text, max_chars):
        """Wrap Arabic text into multiple lines"""
        if not text:
            return []
        
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            word_length = len(word)
            if current_length + word_length <= max_chars:
                current_line.append(word)
                current_length += word_length + 1  # +1 for space
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = word_length
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
    def wrap_text(self, text, max_length):
        """Wrap text into multiple lines"""
        words = text.split()
        lines = []
        current_line = []
        
        for word in words:
            if len(' '.join(current_line + [word])) <= max_length:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
   
    
   
    def contains_arabic(self, text):
        """Check if text contains Arabic characters"""
        if not text:
            return False
        
        # Arabic Unicode range
        arabic_range = range(0x0600, 0x06FF)
        
        for char in str(text):
            if ord(char) in arabic_range:
                return True
        return False
    
    def wrap_arabic_text(self, text, max_chars):
        """Wrap Arabic text into multiple lines"""
        if not text:
            return []
        
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            if current_length + len(word) <= max_chars:
                current_line.append(word)
                current_length += len(word) + 1  # +1 for space
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
    def wrap_text(self, text, max_length):
        """Wrap text into multiple lines"""
        words = text.split()
        lines = []
        current_line = []
        
        for word in words:
            if len(' '.join(current_line + [word])) <= max_length:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines

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
                response.raise_for_status()
                file_content = response.content
            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading certificate from Cloudinary: {e}")
                return Response(
                    {'error': 'Error downloading certificate file'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Check if user wants to force download (via query parameter)
            force_download = request.GET.get('download', 'false').lower() == 'true'
            
            http_response = HttpResponse(file_content, content_type='application/pdf')
            filename = f"certificate_{certificate.verification_code}.pdf"
            
            if force_download:
                # Force download
                http_response['Content-Disposition'] = f'attachment; filename="{filename}"'
            else:
                # Let browser decide (may open in preview)
                http_response['Content-Disposition'] = f'inline; filename="{filename}"'
            
            http_response['Content-Length'] = len(file_content)
            return http_response
            
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

from .models import Payment
class TemporaryEnrollmentView(APIView):
    permission_classes = [IsStudent]
    
    def post(self, request, course_id):
        student = request.user
        
        # Get payment_method from request data
        payment_method = request.data.get('payment_method')
        
        # Validate input data
        serializer = TemporaryEnrollmentSerializer(data={
            'course_id': course_id,
            'payment_method': payment_method
        })
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
        elif Enrollment.objects.filter(
                student=student,
                course=course,
                is_active=False
            ).exists():
            return Response(
                {'error': 'Already enrolled in this course'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Create enrollment without payment
            enrollment = Enrollment.objects.create(
                student=student,
                course=course,
                is_active=False,
                progress_percentage=0.00
            )
        except Exception as e:
            logger.error(f"Enrollment creation failed: {e}")
            return Response(
                {'error': 'Failed to create enrollment. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        try:
            # Use the provided payment_method
            Payment.objects.create(
                student=student, 
                course=course, 
                payment_method=payment_method
            )
        except Exception as e:
            logger.error(f"Payment record creation failed: {e}")
        
        # Update course enrollment count
        course.total_enrollments = course.enrollments.filter(is_active=True).count()
        course.save(update_fields=['total_enrollments'])
        
        return Response({
            'message': 'Successfully enrolled in course',
            'enrollment_id': enrollment.id,
            'student_id': student.id,
            'course': {
                'id': course.id,
                'title': course.title,
                'teacher': course.teacher.full_name
            },
            'enrolled_at': enrollment.enrolled_at,
            'payment_method': payment_method  # Include payment method in response
        }, status=status.HTTP_201_CREATED)
class BulkTemporaryEnrollmentView(APIView):
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
                is_active=False,
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



class PaymentView(generics.ListCreateAPIView):
    serializer_class = PaymentSerializer
    permission_classes = [IsStudent]

    def get_queryset(self):
        return Payment.objects.filter(student=self.request.user)    