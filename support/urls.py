# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('tickets/create/', views.SupportTicketCreateView.as_view(), name='support-ticket-create'),
    path('get/tickets/', views.SupportTicketListView.as_view(), name='support-ticket-list'),
    path('get/tickets/<str:ticket_id>/', views.SupportTicketDetailView.as_view(), name='support-ticket-detail'),
    path('get/ticket/stats/', views.SupportTicketStatsView.as_view(), name='support-ticket-stats'),
]