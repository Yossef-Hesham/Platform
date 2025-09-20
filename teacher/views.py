# teacher/views.py
import traceback
from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.db.models import Avg, Count, Sum, Q
from django.utils import timezone
from datetime import timedelta
from account.models import User

from .models import (
    Course, Section, Quiz, Question, Choice, Enrollment,
    SectionView, QuizAttempt, QuizAnswer, CourseReview
)
from .serializers import (
    CourseListSerializer, CourseCreateUpdateSerializer, CourseDetailSerializer,
    SectionSerializer, QuizSerializer, QuestionSerializer,
    EnrollmentSerializer, SectionViewSerializer, QuizAttemptSerializer,
    QuizAttemptDetailSerializer, CourseReviewSerializer,
    CourseAnalyticsSerializer, QuizAnalyticsSerializer, StudentProgressSerializer,
    BulkEnrollmentSerializer
)


# Custom permission classes
class IsTeacher(permissions.BasePermission):
    """
    Custom permission to only allow teachers to access teacher dashboard
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_teacher

class IsStudent(permissions.BasePermission):
    """
    Custom permission to only allow students to access student dashboard
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_student


class IsTeacherOwner(permissions.BasePermission):
    """
    Custom permission to only allow teachers to access their own content
    """
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'teacher'):
            return obj.teacher == request.user
        elif hasattr(obj, 'course'):
            return obj.course.teacher == request.user
        elif hasattr(obj, 'section'):
            return obj.section.course.teacher == request.user
        elif hasattr(obj, 'quiz'):
            return obj.quiz.section.course.teacher == request.user
        return False


# Course Management Views
class CourseListCreateView(ListCreateAPIView):
    """
    List all courses for authenticated teacher or create a new course
    """
    permission_classes = [IsTeacher]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CourseCreateUpdateSerializer
        return CourseListSerializer
    
    def get_queryset(self):
        return Course.objects.filter(teacher=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(teacher=self.request.user)


class CourseDetailView(RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a course
    """
    permission_classes = [IsTeacher, IsTeacherOwner]
    
    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return CourseCreateUpdateSerializer
        return CourseDetailSerializer
    
    def get_queryset(self):
        return Course.objects.filter(teacher=self.request.user)


# Section Management Views
class SectionListCreateView(APIView):
    """
    List sections for a course or create a new section
    """
    permission_classes = [IsTeacher]
    
    def get_course(self, course_id):
        course = get_object_or_404(Course, id=course_id, teacher=self.request.user)
        return course
    
    def get(self, request, course_id):
        course = self.get_course(course_id)
        sections = course.sections.all()
        serializer = SectionSerializer(sections, many=True)
        return Response(serializer.data)
    
    def post(self, request, course_id):
        course = self.get_course(course_id)
        serializer = SectionSerializer(data=request.data)
        
        if serializer.is_valid():
            section = serializer.save(course=course)
            course.update_statistics()
            return Response(SectionSerializer(section).data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SectionDetailView(RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a section
    """
    serializer_class = SectionSerializer
    permission_classes = [IsTeacher, IsTeacherOwner]
    
    def get_queryset(self):
        return Section.objects.filter(course__teacher=self.request.user)
    
    def perform_destroy(self, instance):
        course = instance.course
        instance.delete()
        course.update_statistics()


# Quiz Management Views
from rest_framework.permissions import IsAuthenticated
class QuizCreateView(generics.CreateAPIView):
    serializer_class = QuizSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_create(self, serializer):
        section_id = self.kwargs['section_id']
        section = get_object_or_404(Section, id=section_id)
        serializer.save(section=section)

class QuizDetailView(RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a quiz
    """
    serializer_class = QuizSerializer
    permission_classes = [IsTeacher, IsTeacherOwner]
    
    def get_queryset(self):
        return Quiz.objects.filter(section__course__teacher=self.request.user)
    
    def perform_destroy(self, instance):
        course = instance.section.course
        instance.delete()
        course.update_statistics()


# Question Management Views
class QuestionListCreateView(APIView):
    """
    List questions for a quiz or create a new question
    """
    permission_classes = [IsTeacher]
    
    def get_quiz(self, quiz_id):
        return get_object_or_404(
            Quiz, 
            id=quiz_id, 
            section__course__teacher=self.request.user
        )
    
    def get(self, request, quiz_id):
        quiz = self.get_quiz(quiz_id)
        questions = quiz.questions.all()
        serializer = QuestionSerializer(questions, many=True)
        return Response(serializer.data)
    
    def post(self, request, quiz_id):
        try:
            quiz = self.get_quiz(quiz_id)
            print(f"Found quiz: {quiz.id}, Title: {quiz.title}")
            
            serializer = QuestionSerializer(data=request.data)
            print(f"Request data: {request.data}")
            
            if serializer.is_valid():
                print("Serializer is valid")
                question = serializer.save(quiz=quiz)
                print(f"Question created: {question.id}")
                return Response(QuestionSerializer(question).data, status=status.HTTP_201_CREATED)
            else:
                print(f"Serializer errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            print(f"500 Error in QuestionListCreateView: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            return Response(
                {'error': 'Internal server error', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class QuestionDetailView(RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a question
    """
    serializer_class = QuestionSerializer
    permission_classes = [IsTeacher, IsTeacherOwner]
    
    def get_queryset(self):
        return Question.objects.filter(quiz__section__course__teacher=self.request.user)


# Enrollment Management Views
class CourseEnrollmentsView(APIView):
    """
    Get all enrollments for teacher's courses
    """
    permission_classes = [IsTeacher]
    
    def get(self, request):
        # Get enrollments for all teacher's courses
        enrollments = Enrollment.objects.filter(
            course__teacher=request.user,
            is_active=True
        ).order_by('-enrolled_at')
        
        # Filter by course if specified
        course_id = request.query_params.get('course_id')
        if course_id:
            enrollments = enrollments.filter(course_id=course_id)
        
        serializer = EnrollmentSerializer(enrollments, many=True)
        return Response(serializer.data)


class BulkEnrollStudentsView(APIView):
    """
    Bulk enroll students in a course
    """
    permission_classes = [IsTeacher]
    
    def post(self, request):
        serializer = BulkEnrollmentSerializer(
            data=request.data, 
            context={'request': request}
        )
        
        if serializer.is_valid():
            course_id = serializer.validated_data['course_id']
            students = serializer.validated_data['student_emails']
            
            course = Course.objects.get(id=course_id)
            enrolled_count = 0
            already_enrolled = []
            
            with transaction.atomic():
                for student in students:
                    enrollment, created = Enrollment.objects.get_or_create(
                        student=student,
                        course=course,
                        defaults={'is_active': True}
                    )
                    
                    if created:
                        enrolled_count += 1
                    else:
                        already_enrolled.append(student.email)
                
                # Update course statistics
                course.update_statistics()
            
            response_data = {
                'enrolled_count': enrolled_count,
                'total_requested': len(students),
                'already_enrolled': already_enrolled
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Analytics and Reporting Views
class TeacherDashboardAnalyticsView(APIView):
    """
    Get overall analytics for teacher's courses
    """
    permission_classes = [IsTeacher]
    
    def get(self, request):
        teacher = request.user
        
        # Get basic statistics
        total_courses = Course.objects.filter(teacher=teacher).count()
        published_courses = Course.objects.filter(teacher=teacher, status='published').count()
        total_enrollments = Enrollment.objects.filter(
            course__teacher=teacher, 
            is_active=True
        ).count()
        
        # Get recent enrollments (last 30 days)
        thirty_days_ago = timezone.now() - timedelta(days=30)
        recent_enrollments = Enrollment.objects.filter(
            course__teacher=teacher,
            enrolled_at__gte=thirty_days_ago
        ).count()
        
        # Calculate total revenue
        total_revenue = Enrollment.objects.filter(
            course__teacher=teacher,
            is_active=True
        ).aggregate(
            total=Sum('course__price')
        )['total'] or 0
        
        # Get top performing courses
        top_courses = Course.objects.filter(teacher=teacher).annotate(
            enrollment_count=Count('enrollments', filter=Q(enrollments__is_active=True)),
            avg_rating=Avg('reviews__rating')
        ).order_by('-enrollment_count')[:5]
        
        course_analytics = []
        for course in top_courses:
            course_analytics.append({
                'id': course.id,
                'title': course.title,
                'enrollments': course.enrollment_count,
                'rating': round(course.avg_rating, 1) if course.avg_rating else 0,
                'revenue': course.enrollment_count * course.price
            })
        
        # Get quiz statistics
        quiz_stats = Quiz.objects.filter(section__course__teacher=teacher).aggregate(
            total_quizzes=Count('id'),
            total_attempts=Sum('total_attempts'),
            avg_score=Avg('average_score')
        )
        
        return Response({
            'overview': {
                'total_courses': total_courses,
                'published_courses': published_courses,
                'total_enrollments': total_enrollments,
                'recent_enrollments': recent_enrollments,
                'total_revenue': total_revenue,
            },
            'top_courses': course_analytics,
            'quiz_statistics': {
                'total_quizzes': quiz_stats['total_quizzes'] or 0,
                'total_attempts': quiz_stats['total_attempts'] or 0,
                'average_score': round(quiz_stats['avg_score'], 1) if quiz_stats['avg_score'] else 0,
            }
        })



class IsTeacherOrStudent(permissions.BasePermission):
    """Allow access to both teachers and students"""
    def has_permission(self, request, view):
        return request.user.user_type in ['teacher', 'student']
    
    
from django.db.models import Max
class CourseAnalyticsView(APIView):
    """
    Get detailed analytics for a specific course
    For Teachers: Full course analytics
    For Students: Personal progress and course overview
    """
    permission_classes = [IsTeacherOrStudent]
    
    def get(self, request, course_id):
        # Get the course - different permission checks for teacher vs student
        if request.user.user_type == 'teacher':
            course = get_object_or_404(Course, id=course_id, teacher=request.user)
        else:  # student
            course = get_object_or_404(Course, id=course_id)
            # Check if student is enrolled
            if not course.enrollments.filter(student=request.user, is_active=True).exists():
                return Response({'error': 'You are not enrolled in this course'}, status=403)
        
        if request.user.user_type == 'teacher':
            return self.get_teacher_analytics(request, course)
        else:
            return self.get_student_analytics(request, course)
    
    def get_teacher_analytics(self, request, course):
        """Teacher-specific analytics"""
        # Basic course statistics
        total_enrollments = course.enrollments.filter(is_active=True).count()
        completed_enrollments = course.enrollments.filter(
            completion_date__isnull=False
        ).count()
        
        completion_rate = (completed_enrollments / total_enrollments * 100) if total_enrollments > 0 else 0
        
        # Average progress
        avg_progress = course.enrollments.filter(is_active=True).aggregate(
            avg=Avg('progress_percentage')
        )['avg'] or 0
        
        # Revenue
        total_revenue = total_enrollments * course.price
        
        # Reviews
        reviews = course.reviews.all()
        avg_rating = reviews.aggregate(avg=Avg('rating'))['avg'] or 0
        
        # Section views analytics
        section_views = []
        for section in course.sections.all():
            views_count = section.views.count()
            unique_viewers = section.views.values('student').distinct().count()
            completion_count = section.views.filter(is_completed=True).count()
            
            section_views.append({
                'section_id': section.id,
                'section_title': section.title,
                'total_views': views_count,
                'unique_viewers': unique_viewers,
                'completion_count': completion_count,
                'completion_rate': (completion_count / views_count * 100) if views_count > 0 else 0
            })
        
        # Quiz performance
        quiz_performance = []
        for section in course.sections.all():
            if hasattr(section, 'quiz'):
                quiz = section.quiz
                attempts = quiz.attempts.filter(is_completed=True)
                
                quiz_performance.append({
                    'quiz_id': quiz.id,
                    'quiz_title': quiz.title,
                    'section_title': section.title,
                    'total_attempts': attempts.count(),
                    'unique_students': attempts.values('student').distinct().count(),
                    'average_score': quiz.average_score,
                    'pass_rate': (attempts.filter(is_passed=True).count() / attempts.count() * 100) if attempts.count() > 0 else 0
                })
        
        # Enrollment timeline (last 6 months)
        enrollment_timeline = []
        for i in range(6):
            month_start = timezone.now().replace(day=1) - timedelta(days=30*i)
            month_end = (month_start + timedelta(days=31)).replace(day=1)
            
            enrollments_count = course.enrollments.filter(
                enrolled_at__gte=month_start,
                enrolled_at__lt=month_end
            ).count()
            
            enrollment_timeline.append({
                'month': month_start.strftime('%Y-%m'),
                'enrollments': enrollments_count
            })
        
        enrollment_timeline.reverse()
        
        return Response({
            'user_type': 'teacher',
            'course_info': {
                'id': course.id,
                'title': course.title,
                'status': course.status,
                'created_at': course.created_at
            },
            'overview': {
                'total_enrollments': total_enrollments,
                'completion_rate': round(completion_rate, 1),
                'average_progress': round(avg_progress, 1),
                'total_revenue': total_revenue,
                'average_rating': round(avg_rating, 1),
                'reviews_count': reviews.count()
            },
            'section_analytics': section_views,
            'quiz_performance': quiz_performance,
            'enrollment_timeline': enrollment_timeline
        })
    
    def get_student_analytics(self, request, course):
        """Student-specific progress data"""
        enrollment = get_object_or_404(
            Enrollment, 
            student=request.user, 
            course=course, 
            is_active=True
        )
        
        # Student's personal progress
        completed_sections = SectionView.objects.filter(
            student=request.user,
            section__course=course,
            is_completed=True
        ).count()
        
        total_sections = course.sections.count()
        
        # Student's quiz performance
        student_quiz_performance = []
        for section in course.sections.all():
            if hasattr(section, 'quiz'):
                quiz = section.quiz
                student_attempts = quiz.attempts.filter(
                    student=request.user,
                    is_completed=True
                ).order_by('-started_at')
                
                latest_attempt = student_attempts.first()
                
                student_quiz_performance.append({
                    'quiz_id': quiz.id,
                    'quiz_title': quiz.title,
                    'section_title': section.title,
                    'attempts_count': student_attempts.count(),
                    'best_score': student_attempts.aggregate(max=Max('score'))['max'] if student_attempts.exists() else None,
                    'latest_score': latest_attempt.score if latest_attempt else None,
                    'is_passed': latest_attempt.is_passed if latest_attempt else False,
                    'last_attempt': latest_attempt.started_at if latest_attempt else None
                })
        
        # Student's section completion status
        section_progress = []
        for section in course.sections.all():
            section_view = SectionView.objects.filter(
                student=request.user,
                section=section
            ).first()
            
            section_progress.append({
                'section_id': section.id,
                'section_title': section.title,
                'is_completed': section_view.is_completed if section_view else False,
                'first_viewed': section_view.first_viewed_at if section_view else None,
                'last_viewed': section_view.last_viewed_at if section_view else None,
                'time_spent_minutes': section_view.total_time_spent_minutes if section_view else 0,
                'order': section.order  # Assuming sections have order field
            })
        
        # Sort sections by order
        section_progress.sort(key=lambda x: x['order'])
        
        # Time spent calculations
        total_time_spent = SectionView.objects.filter(
            student=request.user,
            section__course=course
        ).aggregate(total=Sum('total_time_spent_minutes'))['total'] or 0
        
        # Estimated time to complete
        if enrollment.progress_percentage > 0:
            estimated_total_time = (total_time_spent / enrollment.progress_percentage) * 100
            time_remaining = estimated_total_time - total_time_spent
        else:
            time_remaining = None
        
        return Response({
            'user_type': 'student',
            'course_info': {
                'id': course.id,
                'title': course.title,
                'teacher_name': course.teacher.full_name,
                'start_date': enrollment.enrolled_at
            },
            'progress_overview': {
                'progress_percentage': round(enrollment.progress_percentage, 1),
                'sections_completed': enrollment.sections_completed,
                'total_sections': total_sections,
                'quizzes_passed': enrollment.quizzes_passed,
                'total_time_spent_minutes': total_time_spent,
                'estimated_time_remaining_minutes': round(time_remaining) if time_remaining else None,
                'enrollment_date': enrollment.enrolled_at,
                'completion_date': enrollment.completion_date
            },
            'section_progress': section_progress,
            'quiz_performance': student_quiz_performance,
            'recent_activity': self.get_recent_activity(request.user, course)
        })
    
    def get_recent_activity(self, student, course):
        """Get student's recent activity in the course"""
        section_views = SectionView.objects.filter(
            student=student,
            section__course=course
        ).order_by('-last_viewed_at')[:10]
        
        quiz_attempts = QuizAttempt.objects.filter(
            student=student,
            quiz__section__course=course,
            is_completed=True
        ).order_by('-started_at')[:10]
        
        # Combine and sort activities
        activities = []
        for view in section_views:
            activities.append({
                'type': 'section_view',
                'title': view.section.title,
                'time': view.last_viewed_at,
                'action': 'Viewed section',
                'completed': view.is_completed
            })
        
        for attempt in quiz_attempts:
            activities.append({
                'type': 'quiz_attempt',
                'title': attempt.quiz.title,
                'time': attempt.started_at,
                'action': f'Quiz attempt: {attempt.score}%',
                'passed': attempt.is_passed
            })
        
        # Sort by time and return latest 10
        activities.sort(key=lambda x: x['time'], reverse=True)
        return activities[:10]


class StudentProgressView(APIView):
    """
    Get progress details for students in teacher's courses
    """
    permission_classes = [IsTeacher]
    
    def get(self, request):
        course_id = request.query_params.get('course_id')
        
        if course_id:
            # Get students for specific course
            course = get_object_or_404(Course, id=course_id, teacher=request.user)
            enrollments = course.enrollments.filter(is_active=True)
        else:
            # Get all students from all teacher's courses
            enrollments = Enrollment.objects.filter(
                course__teacher=request.user,
                is_active=True
            )
        
        student_progress = []
        for enrollment in enrollments:
            # Get last activity
            last_section_view = SectionView.objects.filter(
                student=enrollment.student,
                section__course=enrollment.course
            ).order_by('-last_viewed_at').first()
            
            last_quiz_attempt = QuizAttempt.objects.filter(
                student=enrollment.student,
                quiz__section__course=enrollment.course
            ).order_by('-started_at').first()
            
            last_activity = None
            if last_section_view and last_quiz_attempt:
                last_activity = max(last_section_view.last_viewed_at, last_quiz_attempt.started_at)
            elif last_section_view:
                last_activity = last_section_view.last_viewed_at
            elif last_quiz_attempt:
                last_activity = last_quiz_attempt.started_at
            
            # Get quiz statistics
            total_quizzes = Quiz.objects.filter(section__course=enrollment.course).count()
            
            student_progress.append({
                'student_id': enrollment.student.id,
                'student_name': enrollment.student.full_name,
                'student_email': enrollment.student.email,
                'course_title': enrollment.course.title,
                'enrollment_date': enrollment.enrolled_at,
                'progress_percentage': enrollment.progress_percentage,
                'sections_completed': enrollment.sections_completed,
                'total_sections': enrollment.course.total_sections,
                'quizzes_passed': enrollment.quizzes_passed,
                'total_quizzes': total_quizzes,
                'total_time_spent_minutes': enrollment.total_time_spent_minutes,
                'last_activity': last_activity
            })
        
        return Response(student_progress)


class QuizResultsView(APIView):
    """
    Get detailed quiz results for teacher's courses
    """
    permission_classes = [IsTeacher]
    
    def get(self, request):
        quiz_id = request.query_params.get('quiz_id')
        course_id = request.query_params.get('course_id')
        
        # Base queryset
        attempts = QuizAttempt.objects.filter(
            quiz__section__course__teacher=request.user,
            is_completed=True
        )
        
        # Filter by quiz if specified
        if quiz_id:
            attempts = attempts.filter(quiz_id=quiz_id)
        
        # Filter by course if specified
        if course_id:
            attempts = attempts.filter(quiz__section__course_id=course_id)
        
        # Order by most recent
        attempts = attempts.order_by('-completed_at')
        
        serializer = QuizAttemptSerializer(attempts, many=True)
        return Response(serializer.data)


class QuizAttemptDetailView(APIView):
    """
    Get detailed view of a specific quiz attempt with answers
    """
    permission_classes = [IsTeacher]
    
    def get(self, request, attempt_id):
        attempt = get_object_or_404(
            QuizAttempt,
            id=attempt_id,
            quiz__section__course__teacher=request.user
        )
        
        serializer = QuizAttemptDetailSerializer(attempt)
        return Response(serializer.data)


# Course Reviews Management
class CourseReviewsView(APIView):
    """
    Get reviews for teacher's courses
    """
    permission_classes = [IsTeacher]
    
    def get(self, request):
        course_id = request.query_params.get('course_id')
        
        reviews = CourseReview.objects.filter(course__teacher=request.user)
        
        if course_id:
            reviews = reviews.filter(course_id=course_id)
        
        reviews = reviews.order_by('-created_at')
        
        serializer = CourseReviewSerializer(reviews, many=True)
        return Response(serializer.data)


# Utility Views
@api_view(['POST'])
@permission_classes([IsTeacher])
def publish_course(request, course_id):
    """
    Publish a course (change status from draft to published)
    """
    course = get_object_or_404(Course, id=course_id, teacher=request.user)
    
    # Check if course has at least one section
    if not course.sections.exists():
        return Response({
            'error': 'Course must have at least one section before publishing'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    course.status = 'published'
    course.save(update_fields=['status'])
    
    return Response({
        'message': 'Course published successfully',
        'course_id': course.id,
        'status': course.status
    })


@api_view(['POST'])
@permission_classes([IsTeacher])
def archive_course(request, course_id):
    """
    Archive a course
    """
    course = get_object_or_404(Course, id=course_id, teacher=request.user)
    
    course.status = 'archived'
    course.save(update_fields=['status'])
    
    return Response({
        'message': 'Course archived successfully',
        'course_id': course.id,
        'status': course.status
    })


@api_view(['DELETE'])
@permission_classes([IsTeacher])
def remove_student_from_course(request, course_id, student_id):
    """
    Remove a student from a course
    """
    course = get_object_or_404(Course, id=course_id, teacher=request.user)
    enrollment = get_object_or_404(
        Enrollment, 
        course=course, 
        student_id=student_id,
        is_active=True
    )
    
    enrollment.is_active = False
    enrollment.save(update_fields=['is_active'])
    
    # Update course statistics
    course.update_statistics()
    
    return Response({
        'message': 'Student removed from course successfully'
    })
    
    
from rest_framework.permissions import AllowAny
from .serializers import TeacherSerializer

class TeacherListView(APIView):
    # permission_classes = [IsAuthenticated]  # only logged-in users can see

    def get(self, request):
        teachers = User.objects.filter(user_type='teacher')
        serializer = TeacherSerializer(teachers, many=True)
        return Response(serializer.data)
    
from .models import Review
from .serializers import ReviewSerializer, Section_IscompleteSerializer






class ReviewListCreateView(generics.ListCreateAPIView):
    serializer_class = ReviewSerializer

    def get_queryset(self):
        course_id = self.kwargs['course_id']
        return Review.objects.filter(course_id=course_id)

    def perform_create(self, serializer):
        serializer.save(
            user=self.request.user,
            course_id=self.kwargs['course_id']
        )

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsStudent()]




class SectionIsComplete(APIView):
    permission_classes = [IsStudent]
    
    def patch(self, request, section_id):
        try:
            section = get_object_or_404(Section, id=section_id)
            
            # Get or create section view
            section_view, created = SectionView.objects.get_or_create(
                student=request.user,
                section=section
            )
            
            # Always set is_completed to True and save with update_fields
            section_view.is_completed = True
            section_view.save(update_fields=['is_completed'])
            
            serializer = Section_IscompleteSerializer(section_view)
            
            return Response({
                'status': 'success',
                'message': 'Section marked as completed',
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
          

from account.permissions import IsTeacher, IsStudent
# views.py
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Notification, Course
from .serializers import NotificationCreateSerializer

class TeacherSendNotificationView(generics.CreateAPIView):
    serializer_class = NotificationCreateSerializer
    permission_classes = [IsTeacher]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        teacher = request.user
        
        # Determine recipients
        if 'student_ids' in data:
            # Send to specific students
            recipients = User.objects.filter(
                id__in=data['student_ids'],
                user_type='student'
            )
            notification_type = Notification.TEACHER_TO_STUDENTS
        elif 'course' in data:
            # Send to all students in course (verify teacher owns the course)
            course = data['course']
            if course.teacher != teacher:
                return Response(
                    {'error': 'You can only send notifications to your own courses'},
                    status=status.HTTP_403_FORBIDDEN
                )
            recipients = course.enrollments.filter(is_active=True).values_list('student', flat=True)
            notification_type = Notification.TEACHER_TO_COURSE
        else:
            return Response(
                {'error': 'Must specify either student_ids or course'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create notification
        notification = Notification.objects.create(
            sender=teacher,
            title=data['title'],
            message=data['message'],
            course=data.get('course'),
            notification_type=notification_type
        )
        
        # Add recipients
        notification.recipients.set(recipients)
        
        return Response({
            'status': 'success',
            'message': f'Notification sent to {recipients.count()} students',
            'notification_id': notification.id
        }, status=status.HTTP_201_CREATED)