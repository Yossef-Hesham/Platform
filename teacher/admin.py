# teacher/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import (
    Course, Section, Quiz, Question, Choice, Enrollment,
    SectionView, QuizAttempt, QuizAnswer, CourseReview
)


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'teacher', 'status', 'difficulty', 'price',
        'total_enrollments', 'total_sections', 'created_at'
    ]
    list_filter = ['status', 'difficulty', 'created_at', 'teacher']
    search_fields = ['title', 'description', 'teacher__username', 'teacher__email']
    readonly_fields = ['total_sections', 'total_quizzes', 'total_enrollments', 'total_views']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'description', 'teacher', 'thumbnail')
        }),
        ('Course Settings', {
            'fields': ('status', 'difficulty', 'price', 'duration_hours')
        }),
        ('Statistics', {
            'fields': ('total_sections', 'total_quizzes', 'total_enrollments', 'total_views'),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('teacher')


class SectionInline(admin.TabularInline):
    model = Section
    extra = 0
    fields = ['title', 'content_type', 'order', 'duration_minutes']
    readonly_fields = ['total_views']


@admin.register(Section)
class SectionAdmin(admin.ModelAdmin):
    list_display = ['title', 'course', 'content_type', 'order', 'duration_minutes', 'total_views']
    list_filter = ['content_type', 'course__teacher', 'created_at']
    search_fields = ['title', 'course__title', 'course__teacher__username']
    ordering = ['course', 'order']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('course', 'course__teacher')


class ChoiceInline(admin.TabularInline):
    model = Choice
    extra = 2
    fields = ['choice_text', 'is_correct', 'order']


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ['get_question_preview', 'quiz', 'question_type', 'points', 'order']
    list_filter = ['question_type', 'quiz__section__course__teacher', 'created_at']
    search_fields = ['question_text', 'quiz__title', 'quiz__section__course__title']
    inlines = [ChoiceInline]
    ordering = ['quiz', 'order']
    
    def get_question_preview(self, obj):
        return f"{obj.question_text[:50]}..." if len(obj.question_text) > 50 else obj.question_text
    get_question_preview.short_description = 'Question'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'quiz', 'quiz__section', 'quiz__section__course', 'quiz__section__course__teacher'
        )


@admin.register(Quiz)
class QuizAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'get_course_title', 'get_section_title', 
        'time_limit_minutes', 'passing_score', 'total_attempts', 'average_score'
    ]
    list_filter = ['section__course__teacher', 'passing_score', 'created_at']
    search_fields = ['title', 'section__title', 'section__course__title']
    readonly_fields = ['total_attempts', 'average_score']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('section', 'title', 'description')
        }),
        ('Quiz Settings', {
            'fields': ('time_limit_minutes', 'passing_score', 'max_attempts', 'shuffle_questions')
        }),
        ('Statistics', {
            'fields': ('total_attempts', 'average_score'),
            'classes': ('collapse',)
        })
    )
    
    def get_course_title(self, obj):
        return obj.section.course.title
    get_course_title.short_description = 'Course'
    
    def get_section_title(self, obj):
        return obj.section.title
    get_section_title.short_description = 'Section'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'section', 'section__course', 'section__course__teacher'
        )


@admin.register(Enrollment)
class EnrollmentAdmin(admin.ModelAdmin):
    list_display = [
        'get_student_name', 'get_course_title', 'enrolled_at',
        'is_active', 'progress_percentage', 'sections_completed'
    ]
    list_filter = [
        'is_active', 'enrolled_at', 'course__teacher',
        'progress_percentage', 'completion_date'
    ]
    search_fields = [
        'student__username', 'student__email', 'student__first_name',
        'student__last_name', 'course__title'
    ]
    readonly_fields = [
        'progress_percentage', 'sections_completed', 'quizzes_passed',
        'total_time_spent_minutes'
    ]
    date_hierarchy = 'enrolled_at'
    
    fieldsets = (
        ('Enrollment Information', {
            'fields': ('student', 'course', 'enrolled_at', 'is_active')
        }),
        ('Progress Tracking', {
            'fields': (
                'progress_percentage', 'completion_date', 'sections_completed',
                'quizzes_passed', 'total_time_spent_minutes'
            ),
            'classes': ('collapse',)
        })
    )
    
    def get_student_name(self, obj):
        return obj.student.full_name
    get_student_name.short_description = 'Student'
    
    def get_course_title(self, obj):
        return obj.course.title
    get_course_title.short_description = 'Course'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('student', 'course', 'course__teacher')


@admin.register(SectionView)
class SectionViewAdmin(admin.ModelAdmin):
    list_display = [
        'get_student_name', 'get_section_title', 'get_course_title',
        'first_viewed_at', 'total_time_spent_minutes', 'is_completed'
    ]
    list_filter = [
        'is_completed', 'first_viewed_at', 'section__course__teacher'
    ]
    search_fields = [
        'student__username', 'student__email', 'section__title', 'section__course__title'
    ]
    readonly_fields = ['first_viewed_at', 'last_viewed_at']
    date_hierarchy = 'first_viewed_at'
    
    def get_student_name(self, obj):
        return obj.student.full_name
    get_student_name.short_description = 'Student'
    
    def get_section_title(self, obj):
        return obj.section.title
    get_section_title.short_description = 'Section'
    
    def get_course_title(self, obj):
        return obj.section.course.title
    get_course_title.short_description = 'Course'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'student', 'section', 'section__course', 'section__course__teacher'
        )


class QuizAnswerInline(admin.TabularInline):
    model = QuizAnswer
    extra = 0
    readonly_fields = ['question', 'selected_choice', 'text_answer', 'is_correct']
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(QuizAttempt)
class QuizAttemptAdmin(admin.ModelAdmin):
    list_display = [
        'get_student_name', 'get_quiz_title', 'get_course_title',
        'attempt_number', 'score', 'is_passed', 'completed_at'
    ]
    list_filter = [
        'is_completed', 'is_passed', 'quiz__section__course__teacher',
        'started_at', 'completed_at'
    ]
    search_fields = [
        'student__username', 'student__email', 'quiz__title', 'quiz__section__course__title'
    ]
    readonly_fields = [
        'started_at', 'completed_at', 'score', 'total_points',
        'earned_points', 'is_passed', 'time_spent_minutes'
    ]
    inlines = [QuizAnswerInline]
    date_hierarchy = 'started_at'
    
    fieldsets = (
        ('Attempt Information', {
            'fields': ('student', 'quiz', 'attempt_number', 'started_at', 'completed_at', 'is_completed')
        }),
        ('Results', {
            'fields': ('score', 'total_points', 'earned_points', 'is_passed', 'time_spent_minutes'),
            'classes': ('collapse',)
        })
    )
    
    def get_student_name(self, obj):
        return obj.student.full_name
    get_student_name.short_description = 'Student'
    
    def get_quiz_title(self, obj):
        return obj.quiz.title
    get_quiz_title.short_description = 'Quiz'
    
    def get_course_title(self, obj):
        return obj.quiz.section.course.title
    get_course_title.short_description = 'Course'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'student', 'quiz', 'quiz__section', 'quiz__section__course',
            'quiz__section__course__teacher'
        )


@admin.register(QuizAnswer)
class QuizAnswerAdmin(admin.ModelAdmin):
    list_display = [
        'get_student_name', 'get_question_preview', 'get_quiz_title',
        'get_selected_answer', 'is_correct'
    ]
    list_filter = [
        'is_correct', 'question__question_type', 
        'attempt__quiz__section__course__teacher', 'created_at'
    ]
    search_fields = [
        'attempt__student__username', 'attempt__student__email',
        'question__question_text', 'attempt__quiz__title'
    ]
    readonly_fields = ['created_at', 'is_correct']
    
    def get_student_name(self, obj):
        return obj.attempt.student.full_name
    get_student_name.short_description = 'Student'
    
    def get_question_preview(self, obj):
        return f"{obj.question.question_text[:30]}..." if len(obj.question.question_text) > 30 else obj.question.question_text
    get_question_preview.short_description = 'Question'
    
    def get_quiz_title(self, obj):
        return obj.attempt.quiz.title
    get_quiz_title.short_description = 'Quiz'
    
    def get_selected_answer(self, obj):
        if obj.selected_choice:
            return obj.selected_choice.choice_text
        return obj.text_answer[:50] if obj.text_answer else 'No answer'
    get_selected_answer.short_description = 'Selected Answer'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'attempt', 'attempt__student', 'attempt__quiz',
            'question', 'selected_choice'
        )


@admin.register(CourseReview)
class CourseReviewAdmin(admin.ModelAdmin):
    list_display = [
        'get_student_name', 'get_course_title', 'rating',
        'get_review_preview', 'created_at'
    ]
    list_filter = ['rating', 'course__teacher', 'created_at']
    search_fields = [
        'student__username', 'student__email', 'course__title', 'review_text'
    ]
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    def get_student_name(self, obj):
        return obj.student.full_name
    get_student_name.short_description = 'Student'
    
    def get_course_title(self, obj):
        return obj.course.title
    get_course_title.short_description = 'Course'
    
    def get_review_preview(self, obj):
        if obj.review_text:
            return f"{obj.review_text[:50]}..." if len(obj.review_text) > 50 else obj.review_text
        return 'No review text'
    get_review_preview.short_description = 'Review'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('student', 'course', 'course__teacher')


@admin.register(Choice)
class ChoiceAdmin(admin.ModelAdmin):
    list_display = [
        'get_choice_preview', 'get_question_preview', 'get_quiz_title',
        'is_correct', 'order'
    ]
    list_filter = ['is_correct', 'question__question_type', 'question__quiz__section__course__teacher']
    search_fields = [
        'choice_text', 'question__question_text', 'question__quiz__title'
    ]
    ordering = ['question', 'order']
    
    def get_choice_preview(self, obj):
        return f"{obj.choice_text[:40]}..." if len(obj.choice_text) > 40 else obj.choice_text
    get_choice_preview.short_description = 'Choice Text'
    
    def get_question_preview(self, obj):
        return f"{obj.question.question_text[:30]}..." if len(obj.question.question_text) > 30 else obj.question.question_text
    get_question_preview.short_description = 'Question'
    
    def get_quiz_title(self, obj):
        return obj.question.quiz.title
    get_quiz_title.short_description = 'Quiz'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'question', 'question__quiz', 'question__quiz__section',
            'question__quiz__section__course'
        )


# Custom admin site configuration
admin.site.site_header = "Teacher Dashboard Administration"
admin.site.site_title = "Teacher Dashboard Admin"
admin.site.index_title = "Welcome to Teacher Dashboard Administration"