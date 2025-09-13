from django.shortcuts import render
from django.db import models
# Create your views here.
# views.py
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from .models import SupportTicket
from .serializers import SupportTicketSerializer, SupportTicketCreateSerializer, SupportTicketUpdateSerializer
from Admin.permissions import IsAdminUser

class SupportTicketCreateView(generics.CreateAPIView):
    """Create a new support ticket (public endpoint)"""
    queryset = SupportTicket.objects.all()
    serializer_class = SupportTicketCreateSerializer
    
    def perform_create(self, serializer):
        serializer.save()

class SupportTicketListView(generics.ListAPIView):
    """List all support tickets (admin only)"""
    permission_classes = [IsAdminUser]
    serializer_class = SupportTicketSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'priority', 'category']
    search_fields = ['ticket_id', 'name', 'email', 'subject']
    ordering_fields = ['created_at', 'updated_at', 'priority']
    ordering = ['-created_at']
    
    def get_queryset(self):
        return SupportTicket.objects.all()

class SupportTicketDetailView(generics.RetrieveUpdateAPIView):
    """Retrieve or update a support ticket (admin only)"""
    permission_classes = [IsAdminUser]
    queryset = SupportTicket.objects.all()
    serializer_class = SupportTicketUpdateSerializer
    lookup_field = 'ticket_id'

class SupportTicketStatsView(APIView):
    """Get support ticket statistics (admin only)"""
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        stats = {
            'total_tickets': SupportTicket.objects.count(),
            'open_tickets': SupportTicket.objects.filter(status='open').count(),
            'in_progress_tickets': SupportTicket.objects.filter(status='in_progress').count(),
            'resolved_tickets': SupportTicket.objects.filter(status='resolved').count(),
            'by_category': SupportTicket.objects.values('category').annotate(count=models.Count('id')),
            'by_priority': SupportTicket.objects.values('priority').annotate(count=models.Count('id')),
            'recent_tickets': SupportTicket.objects.order_by('-created_at')[:5].values('ticket_id', 'subject', 'status', 'created_at')
        }
        return Response(stats)
    
# views.py
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from .models import SupportMessage
from .serializers import SupportMessageSerializer, SupportMessageCreateSerializer
from Admin.permissions import IsAdminUser

class SupportMessageCreateView(generics.CreateAPIView):
    """Create a new support message (public endpoint)"""
    queryset = SupportMessage.objects.all()
    serializer_class = SupportMessageCreateSerializer

class SupportMessageListView(generics.ListAPIView):
    """List all support messages (admin only)"""
    permission_classes = [IsAdminUser]
    serializer_class = SupportMessageSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['ticket_id', 'name', 'email', 'message']
    ordering_fields = ['created_at', 'name']
    ordering = ['-created_at']
    
    def get_queryset(self):
        return SupportMessage.objects.all()

class SupportMessageDetailView(generics.RetrieveAPIView):
    """Retrieve a support message (admin only)"""
    permission_classes = [IsAdminUser]
    queryset = SupportMessage.objects.all()
    serializer_class = SupportMessageSerializer
    lookup_field = 'ticket_id'

class SupportMessageStatsView(APIView):
    """Get support message statistics (admin only)"""
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        from django.db.models import Count
        from django.utils import timezone
        from datetime import timedelta
        
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        
        stats = {
            'total_messages': SupportMessage.objects.count(),
            'today_messages': SupportMessage.objects.filter(created_at__date=today).count(),
            'week_messages': SupportMessage.objects.filter(created_at__date__gte=week_ago).count(),
            'recent_messages': list(SupportMessage.objects.order_by('-created_at')[:10].values(
                'ticket_id', 'name', 'email', 'created_at'
            ))
        }
        return Response(stats)