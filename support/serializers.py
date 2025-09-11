# serializers.py
from rest_framework import serializers
from .models import SupportTicket

class SupportTicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportTicket
        fields = [
            'ticket_id', 'name', 'email', 'phone_number', 'subject',
            'category', 'priority', 'description', 'status', 'created_at',
            'updated_at', 'admin_notes'
        ]
        read_only_fields = ['ticket_id', 'status', 'created_at', 'updated_at', 'admin_notes']

class SupportTicketCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportTicket
        fields = [
            'name', 'email', 'phone_number', 'subject',
            'category', 'priority', 'description'
        ]

class SupportTicketUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportTicket
        fields = ['status', 'admin_notes']