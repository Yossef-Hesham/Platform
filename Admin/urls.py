# urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Dashboard endpoints
    path('dashboard/stats/', views.AdminDashboardStatsView.as_view(), name='admin-dashboard-stats'),
    # path('dashboard/financials/', views.AdminFinancialView.as_view(), name='admin-financials'),
    
    # User management
    path('users/', views.AdminUserListView.as_view(), name='admin-users-list'),
    path('users/<int:pk>/', views.AdminUserDetailView.as_view(), name='admin-user-detail'),
    path('users/create/', views.AdminUserCreateView.as_view(), name='admin-user-create'),
    path('users/<int:pk>/delete/', views.AdminUserDeleteView.as_view(), name='admin-user-delete'),
    
    # Course management
    path('courses/', views.AdminCourseListView.as_view(), name='admin-courses-list'),
    path('courses/<int:pk>/', views.AdminCourseDetailView.as_view(), name='admin-course-detail'),
    path('courses/<int:course_id>/approve/', views.AdminCourseApproveView.as_view(), name='admin-course-approve'),
    
    # Add more endpoints as needed...
]