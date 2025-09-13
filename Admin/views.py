from django.shortcuts import get_object_or_404, render

# Create your views here.
# views.py
from django.db.models import Count, Sum, Avg, Q
from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from teacher.models import User, Course, Enrollment, Section, Quiz, QuizAttempt
from .permissions import IsAdminUser
class AdminDashboardStatsView(APIView):
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        try:
            # Calculate date ranges
            today = timezone.now().date()
            week_ago = today - timedelta(days=7)
            month_ago = today - timedelta(days=30)
            
            # User statistics
            total_users = User.objects.count()
            new_users_today = User.objects.filter(date_joined__date=today).count()
            new_users_week = User.objects.filter(date_joined__date__gte=week_ago).count()
            new_users_month = User.objects.filter(date_joined__date__gte=month_ago).count()
            
            user_types = User.objects.values('user_type').annotate(count=Count('id'))
            
            # Course statistics
            total_courses = Course.objects.count()
            published_courses = Course.objects.filter(status='published').count()
            draft_courses = Course.objects.filter(status='draft').count()
            
            # Enrollment statistics - USING CORRECT FIELD NAMES
            total_enrollments = Enrollment.objects.filter(is_active=True).count()
            # Use 'enrolled_at' instead of 'created_at'
            new_enrollments_today = Enrollment.objects.filter(enrolled_at__date=today).count()
            
            # Quiz statistics
            total_quiz_attempts = QuizAttempt.objects.filter(is_completed=True).count()
            avg_quiz_score = QuizAttempt.objects.filter(is_completed=True).aggregate(
                avg_score=Avg('score')
            )['avg_score'] or 0
            
            return Response({
                "user_analytics": {
                    "total_users": total_users,
                    "new_users_today": new_users_today,
                    "new_users_week": new_users_week,
                    "new_users_month": new_users_month,
                    "user_type_distribution": {item['user_type']: item['count'] for item in user_types}
                },
                "course_analytics": {
                    "total_courses": total_courses,
                    "published_courses": published_courses,
                    "draft_courses": draft_courses,
                    "courses_by_difficulty": self.get_courses_by_difficulty()
                },
                "enrollment_analytics": {
                    "total_enrollments": total_enrollments,
                    "new_enrollments_today": new_enrollments_today,
                    "avg_enrollments_per_course": self.get_avg_enrollments()
                },
                "learning_analytics": {
                    "total_quiz_attempts": total_quiz_attempts,
                    "average_quiz_score": round(float(avg_quiz_score), 2),
                    "completion_rates": self.get_completion_rates()
                },
                "system_health": {
                    "active_users_today": User.objects.filter(last_login__date=today).count(),
                    "active_courses_today": self.get_active_courses_today(),
                    "system_uptime": "99.98%"
                }
            })
            
        except Exception as e:
            print(f"Error in AdminDashboardStatsView: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return Response(
                {"error": "Internal server error", "details": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_courses_by_difficulty(self):
        try:
            return list(Course.objects.values('difficulty').annotate(count=Count('id')))
        except Exception as e:
            print(f"Error in get_courses_by_difficulty: {str(e)}")
            return []
    
    def get_avg_enrollments(self):
        try:
            # Use 'enrolled_at' instead of 'created_at'
            courses_with_enrollments = Enrollment.objects.filter(
                is_active=True
            ).values('course').annotate(
                enrollment_count=Count('id')
            )
            
            if not courses_with_enrollments:
                return 0
                
            total_enrollments = sum(item['enrollment_count'] for item in courses_with_enrollments)
            total_courses = len(courses_with_enrollments)
            
            return round(total_enrollments / total_courses, 2) if total_courses > 0 else 0
            
        except Exception as e:
            print(f"Error in get_avg_enrollments: {str(e)}")
            return 0
    
    def get_completion_rates(self):
        try:
            # Get total quizzes
            total_quizzes = Quiz.objects.count()
            if total_quizzes == 0:
                return 0
                
            # Get distinct quizzes that have been completed
            completed_quizzes = QuizAttempt.objects.filter(
                is_completed=True
            ).values('quiz').distinct().count()
            
            return round((completed_quizzes / total_quizzes * 100), 2)
            
        except Exception as e:
            print(f"Error in get_completion_rates: {str(e)}")
            return 0
    
    def get_active_courses_today(self):
        try:
            # Count courses that have had any activity today
            today = timezone.now().date()
            # Use 'enrolled_at' instead of 'created_at' for enrollments
            # Use 'completed_at' for quiz attempts
            active_courses = Course.objects.filter(
                Q(sections__quiz__attempts__completed_at__date=today) |
                Q(enrollments__enrolled_at__date=today)
            ).distinct().count()
            
            return active_courses
            
        except Exception as e:
            print(f"Error in get_active_courses_today: {str(e)}")
            return 0
# views.py

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, filters
from .serializers import UserSerializer

class AdminUserListView(generics.ListAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['user_type', 'is_active', 'email_verified']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering_fields = ['date_joined', 'last_login', 'username']
    
    def get_queryset(self):
        return User.objects.all().order_by('-date_joined')

class AdminUserDetailView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer
    queryset = User.objects.all()
    
    def update(self, request, *args, **kwargs):
        # Add admin-specific update logic here
        return super().update(request, *args, **kwargs)

class AdminUserCreateView(generics.CreateAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer
    
    def perform_create(self, serializer):
        # Add admin-specific creation logic
        user = serializer.save()
        # Additional admin actions here

class AdminUserDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAdminUser]
    queryset = User.objects.all()
    
    def perform_destroy(self, instance):
        # Add custom delete logic
        instance.delete()
        
        
# views.py
from .serializers import CourseSerializer

class AdminCourseListView(generics.ListAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = CourseSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['status', 'difficulty', 'teacher']
    search_fields = ['title', 'description']
    
    def get_queryset(self):
        return Course.objects.all().select_related('teacher').prefetch_related('sections')

class AdminCourseDetailView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = CourseSerializer
    queryset = Course.objects.all()
    
    def update(self, request, *args, **kwargs):
        # Admin can change course status, etc.
        return super().update(request, *args, **kwargs)



class AdminCourseApproveView(APIView):
    permission_classes = [IsAdminUser]
    
    def post(self, request, course_id):
        course = get_object_or_404(Course, id=course_id)
        if course.status == 'draft':
            course.status = 'published'
            course.save()
            return Response({"message": "Course published successfully"})
        return Response({"error": "Course is not in draft status"}, status=400)
    
# views.py
# class AdminFinancialView(APIView):
    # permission_classes = [IsAdminUser]
    
    # def get(self, request):
    #     # Revenue by time period
    #     revenue_today = Payment.objects.filter(
    #         status='completed',
    #         created_at__date=timezone.now().date()
    #     ).aggregate(total=Sum('amount'))['total'] or 0
        
    #     revenue_week = Payment.objects.filter(
    #         status='completed',
    #         created_at__date__gte=timezone.now().date() - timedelta(days=7)
    #     ).aggregate(total=Sum('amount'))['total'] or 0
        
    #     revenue_month = Payment.objects.filter(
    #         status='completed', 
    #         created_at__date__gte=timezone.now().date() - timedelta(days=30)
    #     ).aggregate(total=Sum('amount'))['total'] or 0
        
    #     # Top earning courses
    #     top_courses = Payment.objects.filter(
    #         status='completed'
    #     ).values(
    #         'course__title'
    #     ).annotate(
    #         revenue=Sum('amount'),
    #         enrollments=Count('id')
    #     ).order_by('-revenue')[:10]
        
    #     # Payment method distribution
    #     # payment_methods = Payment.objects.filter(
    #     #     status='completed'
    #     # ).values('payment_method').annotate(
    #     #     count=Count('id'),
    #     #     total=Sum('amount')
    #     # )
        
    #     return Response({
    #         "revenue_summary": {
    #             "today": float(revenue_today),
    #             "this_week": float(revenue_week),
    #             "this_month": float(revenue_month),
    #             "all_time": float(Payment.objects.filter(status='completed').aggregate(total=Sum('amount'))['total'] or 0)
    #         },
    #         "top_earning_courses": list(top_courses),
    #          "payment_methods": list(payment_methods),
    #          "revenue_trend": self.get_revenue_trend(30)  # Last 30 days
    #     })
    
    # def get_revenue_trend(self, days):
    #     trend = []
    #     for i in range(days):
    #         date = timezone.now().date() - timedelta(days=i)
    #         daily_revenue = Payment.objects.filter(
    #             status='completed',
    #             created_at__date=date
    #         ).aggregate(total=Sum('amount'))['total'] or 0
    #         trend.append({"date": date, "revenue": float(daily_revenue)})
    #     return trend[::-1]