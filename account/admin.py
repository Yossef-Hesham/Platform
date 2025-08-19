from django.contrib import admin

# Register your models here.
from .models import User, TeacherProfile, StudentProfile, TEST



admin.site.register(User)
admin.site.register(TeacherProfile)
admin.site.register(StudentProfile)
admin.site.register(TEST)