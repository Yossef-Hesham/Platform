# teacher/urls.py
from django.urls import path
from . import views

app_name = 'teacher'

urlpatterns = [
    # Course Management
    path('courses/', views.CourseListCreateView.as_view(), name='course_list_create'),
    path('courses/<int:pk>/', views.CourseDetailView.as_view(), name='course_detail'),
    path('courses/<int:course_id>/publish/', views.publish_course, name='publish_course'),
    path('courses/<int:course_id>/archive/', views.archive_course, name='archive_course'),
    
    # Section Management
    path('courses/<int:course_id>/sections/', views.SectionListCreateView.as_view(), name='section_list_create'),
    path('sections/<int:pk>/', views.SectionDetailView.as_view(), name='section_detail'),
    
    # Quiz Management
    path('sections/<int:section_id>/quiz/', views.QuizCreateView.as_view(), name='quiz_create'),
    path('quizzes/<int:pk>/', views.QuizDetailView.as_view(), name='quiz_detail'),
    
    # Question Management
    path('quizzes/<int:quiz_id>/questions/', views.QuestionListCreateView.as_view(), name='question_list_create'),
    path('questions/<int:pk>/', views.QuestionDetailView.as_view(), name='question_detail'),
    
    # Student Enrollment Management
    path('enrollments/', views.CourseEnrollmentsView.as_view(), name='course_enrollments'),
    path('enrollments/bulk/', views.BulkEnrollStudentsView.as_view(), name='bulk_enroll_students'),
    path('courses/<int:course_id>/students/<int:student_id>/remove/', views.remove_student_from_course, name='remove_student'),
    
    # Analytics and Reporting
    path('analytics/dashboard/', views.TeacherDashboardAnalyticsView.as_view(), name='dashboard_analytics'),
    path('analytics/courses/<int:course_id>/', views.CourseAnalyticsView.as_view(), name='course_analytics'),
    path('analytics/students/', views.StudentProgressView.as_view(), name='student_progress'),
    
    # Quiz Results and Analysis
    path('quiz-results/', views.QuizResultsView.as_view(), name='quiz_results'),
    path('quiz-attempts/<int:attempt_id>/', views.QuizAttemptDetailView.as_view(), name='quiz_attempt_detail'),

    path('get_teachers/', views.TeacherListView.as_view(), name='get_all_teachers'),

    # Course Reviews
    path('reviews/', views.CourseReviewsView.as_view(), name='course_reviews'),
]