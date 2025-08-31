# teacherdashboard/apps.py
from django.apps import AppConfig


class TeacherdashboardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'teacher'
    verbose_name = 'Teacher Dashboard'
    
    def ready(self):
        import teacher.signals