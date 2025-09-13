# admin.py
from django.contrib import admin
from .models import SupportTicket

@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    list_display = ['ticket_id', 'subject', 'name', 'email', 'status', 'priority', 'created_at']
    list_filter = ['status', 'priority', 'category', 'created_at']
    search_fields = ['ticket_id', 'name', 'email', 'subject']
    readonly_fields = ['ticket_id', 'created_at', 'updated_at']
    
# admin.py
from .models import SupportMessage

@admin.register(SupportMessage)
class SupportMessageAdmin(admin.ModelAdmin):
    list_display = ['ticket_id', 'name', 'email', 'created_at']
    list_filter = ['created_at']
    search_fields = ['ticket_id', 'name', 'email', 'message']
    readonly_fields = ['ticket_id', 'created_at']