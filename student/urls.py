from django.urls import path
from . import views
from teacher.views import SectionIsComplete, SecionIscompleteView
app_name = 'student'

urlpatterns = [
    path('get-all-courses/', views.GETAllCourses.as_view(), name='get_all_courses'),
    path('dashboard/', views.StudentDashboardView.as_view(), name='dashboard'),
    path('my-courses/', views.MyCoursesView.as_view(), name='my_courses'),
    path('course/<int:course_id>/', views.CourseContentView.as_view(), name='course_content'),
    path('course/<int:course_id>/section/<int:section_order>/', views.SectionDetailView.as_view(), name='section_detail'),


    path('course/<int:course_id>/section/<int:section_id>/quiz/<int:quiz_id>/', views.TakeQuizView.as_view(), name='take_quiz'),

    path('quiz-results/<int:attempt_id>/', views.QuizResultsView.as_view(), name='quiz_results'),
    # path('notes/<int:section_id>/', views.StudentNotesView.as_view(), name='student_notes'),
    path('certificates/<int:course_id>/', views.CertificateView.as_view(), name='certificate'),
    path('certificates/download/<int:certificate_id>/', views.CertificateDownloadView.as_view(), name='certificate_download'),

    path('enroll/temporary/<int:course_id>/', views.TemporaryEnrollmentView.as_view(), name='temporary_enrollment'),
    path('enroll/temporary/bulk/', views.BulkTemporaryEnrollmentView.as_view(), name='bulk_temporary_enrollment'),
    # path('admin/enroll/', views.AdminEnrollmentView.as_view(), name='admin_enrollment'),
    
    path('enrollments/', views.EnrollmentListView.as_view(), name='enrollment_list'),
    path('recommendations/', views.CourseRecommendationsView.as_view(), name='course_recommendations'),
    path('statistics/', views.LearningStatisticsView.as_view(), name='learning_statistics'),
    
    
    # i should test these two paths on postman
    path('sections/<int:section_id>/download-pdf/', views.SectionPDFDownloadView.as_view(), name='download_section_pdf'),
    path('courses/<int:course_id>/pdfs/', views.CourseAllPDFsDownloadView.as_view(), name='course_pdfs_list'),

    # Section Completion
    path('sections/<int:section_id>/complete/', SecionIscompleteView.as_view(), name='section_is_complete'),


]