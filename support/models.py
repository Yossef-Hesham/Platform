# models.py
import random
from django.db import models
from django.core.mail import send_mail
from django.conf import settings

class SupportTicket(models.Model):
    TICKET_STATUS = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]
    
    TICKET_PRIORITY = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('urgent', 'Urgent'),
    ]
    
    TICKET_CATEGORY = [
        ('technical', 'Technical Issue'),
        ('billing', 'Billing/Payment'),
        ('account', 'Account Issue'),
        ('content', 'Content Related'),
        ('general', 'General Inquiry'),
        ('bug', 'Bug Report'),
        ('feature', 'Feature Request'),
    ]
    
    # Auto-generated 4-digit ticket ID
    ticket_id = models.CharField(max_length=4, unique=True, editable=False)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    subject = models.CharField(max_length=200)
    category = models.CharField(max_length=20, choices=TICKET_CATEGORY, default='general')
    priority = models.CharField(max_length=20, choices=TICKET_PRIORITY, default='medium')
    description = models.TextField()
    status = models.CharField(max_length=20, choices=TICKET_STATUS, default='open')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    admin_notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.ticket_id} - {self.subject}"
    
    def save(self, *args, **kwargs):
        if not self.ticket_id:
            # Generate unique 4-digit ticket ID
            self.ticket_id = self.generate_ticket_id()
            
            # Send email notification to admin
            self.send_admin_notification()
        
        super().save(*args, **kwargs)
    
    def generate_ticket_id(self):
        """Generate a unique 4-digit ticket ID"""
        while True:
            ticket_id = str(random.randint(1000, 9999))
            if not SupportTicket.objects.filter(ticket_id=ticket_id).exists():
                return ticket_id
    
    def send_admin_notification(self):
        """Send email notification to admin about new ticket"""
        subject = f"New Support Ticket: #{self.ticket_id} - {self.subject}"
        
        message = f"""
        New support ticket has been created:
        
        Ticket ID: #{self.ticket_id}
        Subject: {self.subject}
        Category: {self.get_category_display()}
        Priority: {self.get_priority_display()}
        Submitted by: {self.name}
        Email: {self.email}
        Phone: {self.phone_number or 'Not provided'}
        
        Description:
        {self.description}
        
        Please log in to the admin panel to view and manage this ticket.
        """
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=self.email,
                recipient_list=[settings.ADMIN_EMAIL],  # Add admin email in settings
                fail_silently=False,
            )
        except Exception as e:
            # Log error but don't prevent ticket creation
            print(f"Failed to send email notification: {str(e)}")