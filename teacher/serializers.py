# teacher/serializers.py
from rest_framework import serializers
from django.db import transaction
from account.models import User
from .models import (
    Course, Section, Quiz, Question, Choice, Enrollment,
    SectionView, QuizAttempt, QuizAnswer, CourseReview
)


class CourseListSerializer(serializers.ModelSerializer):
    """
    Serializer for course list view
    """
    teacher_name = serializers.ReadOnlyField(source='teacher.full_name')
    average_rating = serializers.SerializerMethodField()
    
    class Meta:
        model = Course
        fields = [
            'id', 'title', 'description', 'teacher_name', 'thumbnail',
            'status', 'difficulty', 'price', 'duration_hours',
            'total_sections', 'total_quizzes', 'total_enrollments',
            'average_rating', 'created_at', 'updated_at'
        ]
    
    def get_average_rating(self, obj):
        reviews = obj.reviews.all()
        if reviews:
            return round(sum([review.rating for review in reviews]) / len(reviews), 1)
        return 0.0


class CourseCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating and updating courses
    """
    class Meta:
        model = Course
        fields = [
            'title', 'description', 'thumbnail', 'status', 'difficulty',
            'price', 'duration_hours'
        ]
    
    def create(self, validated_data):
        validated_data['teacher'] = self.context['request'].user
        return super().create(validated_data)


class ChoiceSerializer(serializers.ModelSerializer):
    """
    Serializer for question choices
    """
    class Meta:
        model = Choice
        fields = ['id', 'choice_text', 'is_correct', 'order']


class QuestionSerializer(serializers.ModelSerializer):
    """
    Serializer for quiz questions
    """
    choices = ChoiceSerializer(many=True, required=False)
    
    class Meta:
        model = Question
        fields = [
            'id', 'question_text', 'question_type', 'points', 'order',
            'explanation', 'choices'
        ]
    
    def create(self, validated_data):
        choices_data = validated_data.pop('choices', [])
        question = Question.objects.create(**validated_data)
        
        for choice_data in choices_data:
            Choice.objects.create(question=question, **choice_data)
        
        return question
    
    def update(self, instance, validated_data):
        choices_data = validated_data.pop('choices', [])
        
        # Update question fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update choices
        if choices_data:
            # Delete existing choices
            instance.choices.all().delete()
            
            # Create new choices
            for choice_data in choices_data:
                Choice.objects.create(question=instance, **choice_data)
        
        return instance


class QuizSerializer(serializers.ModelSerializer):
    """
    Serializer for quizzes
    """
    questions = QuestionSerializer(many=True, required=False)  # Remove read_only=True
    question_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Quiz
        fields = [
            'id', 'title', 'description', 'time_limit_minutes',
            'passing_score', 'max_attempts', 'shuffle_questions',
            'total_attempts', 'average_score', 'questions',
            'question_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['total_attempts', 'average_score']
    
    def get_question_count(self, obj):
        return obj.questions.count()
    
    def create(self, validated_data):
        questions_data = validated_data.pop('questions', [])
        quiz = Quiz.objects.create(**validated_data)
        
        for question_data in questions_data:
            choices_data = question_data.pop('choices', [])
            question = Question.objects.create(quiz=quiz, **question_data)
            
            for choice_data in choices_data:
                Choice.objects.create(question=question, **choice_data)
        
        return quiz
    
    def update(self, instance, validated_data):
        questions_data = validated_data.pop('questions', [])
        
        # Update quiz fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update questions
        if questions_data:
            # Delete existing questions and choices
            instance.questions.all().delete()
            
            # Create new questions with choices
            for question_data in questions_data:
                choices_data = question_data.pop('choices', [])
                question = Question.objects.create(quiz=instance, **question_data)
                
                for choice_data in choices_data:
                    Choice.objects.create(question=question, **choice_data)
        
        return instance
class SectionSerializer(serializers.ModelSerializer):
    """
    Serializer for course sections
    """
    quiz = QuizSerializer(required=False, allow_null=True)
    has_quiz = serializers.SerializerMethodField()
    
    class Meta:
        model = Section
        fields = [
            'id', 'title', 'description', 'content_type', 'content',
            'video_file', 'pdf_file', 'order', 'duration_minutes',
            'total_views', 'quiz', 'has_quiz', 'created_at', 'updated_at'
        ]
    
    def get_has_quiz(self, obj):
        return hasattr(obj, 'quiz')
    
    def create(self, validated_data):
        quiz_data = validated_data.pop('quiz', None)
        section = Section.objects.create(**validated_data)
        
        if quiz_data:
            # Create quiz for this section
            Quiz.objects.create(section=section, **quiz_data)
        
        return section
    
    def update(self, instance, validated_data):
        quiz_data = validated_data.pop('quiz', None)
        
        # Update section fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Handle quiz update or creation
        if quiz_data is not None:
            if hasattr(instance, 'quiz'):
                # Update existing quiz
                quiz_serializer = QuizSerializer(instance.quiz, data=quiz_data, partial=True)
                quiz_serializer.is_valid(raise_exception=True)
                quiz_serializer.save()
            else:
                # Create new quiz
                Quiz.objects.create(section=instance, **quiz_data)
        
        return instance

class CourseDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for course with sections
    """
    teacher_name = serializers.ReadOnlyField(source='teacher.full_name')
    sections = SectionSerializer(many=True, read_only=True)
    average_rating = serializers.SerializerMethodField()
    reviews_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Course
        fields = [
            'id', 'title', 'description', 'teacher_name', 'thumbnail',
            'status', 'difficulty', 'price', 'duration_hours',
            'total_sections', 'total_quizzes', 'total_enrollments',
            'total_views', 'sections', 'average_rating', 'reviews_count',
            'created_at', 'updated_at'
        ]
    
    def get_average_rating(self, obj):
        reviews = obj.reviews.all()
        if reviews:
            return round(sum([review.rating for review in reviews]) / len(reviews), 1)
        return 0.0
    
    def get_reviews_count(self, obj):
        return obj.reviews.count()


class EnrollmentSerializer(serializers.ModelSerializer):
    """
    Serializer for student enrollments
    """
    student_name = serializers.ReadOnlyField(source='student.full_name')
    student_email = serializers.ReadOnlyField(source='student.email')
    course_title = serializers.ReadOnlyField(source='course.title')
    
    class Meta:
        model = Enrollment
        fields = [
            'id', 'student_name', 'student_email', 'course_title',
            'enrolled_at', 'is_active', 'progress_percentage',
            'completion_date', 'total_time_spent_minutes',
            'sections_completed', 'quizzes_passed'
        ]


class SectionViewSerializer(serializers.ModelSerializer):
    """
    Serializer for section views
    """
    student_name = serializers.ReadOnlyField(source='student.full_name')
    section_title = serializers.ReadOnlyField(source='section.title')
    course_title = serializers.ReadOnlyField(source='section.course.title')
    
    class Meta:
        model = SectionView
        fields = [
            'id', 'student_name', 'section_title', 'course_title',
            'first_viewed_at', 'last_viewed_at', 'total_time_spent_minutes',
            'is_completed'
        ]


class QuizAttemptSerializer(serializers.ModelSerializer):
    """
    Serializer for quiz attempts
    """
    student_name = serializers.ReadOnlyField(source='student.full_name')
    student_email = serializers.ReadOnlyField(source='student.email')
    quiz_title = serializers.ReadOnlyField(source='quiz.title')
    course_title = serializers.ReadOnlyField(source='quiz.section.course.title')
    
    class Meta:
        model = QuizAttempt
        fields = [
            'id', 'student_name', 'student_email', 'quiz_title',
            'course_title', 'attempt_number', 'started_at',
            'completed_at', 'is_completed', 'score', 'total_points',
            'earned_points', 'time_spent_minutes', 'is_passed'
        ]


class QuizAnswerSerializer(serializers.ModelSerializer):
    """
    Serializer for quiz answers
    """
    question_text = serializers.ReadOnlyField(source='question.question_text')
    correct_answer = serializers.SerializerMethodField()
    selected_answer = serializers.SerializerMethodField()
    
    class Meta:
        model = QuizAnswer
        fields = [
            'id', 'question_text', 'selected_answer', 'correct_answer',
            'text_answer', 'is_correct'
        ]
    
    def get_correct_answer(self, obj):
        if obj.question.question_type in ['multiple_choice', 'true_false']:
            correct_choice = obj.question.choices.filter(is_correct=True).first()
            return correct_choice.choice_text if correct_choice else None
        return None
    
    def get_selected_answer(self, obj):
        if obj.selected_choice:
            return obj.selected_choice.choice_text
        return obj.text_answer


class QuizAttemptDetailSerializer(QuizAttemptSerializer):
    """
    Detailed serializer for quiz attempts with answers
    """
    answers = QuizAnswerSerializer(many=True, read_only=True)
    
    class Meta(QuizAttemptSerializer.Meta):
        fields = QuizAttemptSerializer.Meta.fields + ['answers']


class CourseReviewSerializer(serializers.ModelSerializer):
    """
    Serializer for course reviews
    """
    student_name = serializers.ReadOnlyField(source='student.full_name')
    course_title = serializers.ReadOnlyField(source='course.title')
    
    class Meta:
        model = CourseReview
        fields = [
            'id', 'student_name', 'course_title', 'rating',
            'review_text', 'created_at', 'updated_at'
        ]


# Analytics Serializers
class CourseAnalyticsSerializer(serializers.Serializer):
    """
    Serializer for course analytics data
    """
    course_id = serializers.IntegerField()
    course_title = serializers.CharField()
    total_enrollments = serializers.IntegerField()
    active_enrollments = serializers.IntegerField()
    completion_rate = serializers.DecimalField(max_digits=5, decimal_places=2)
    average_progress = serializers.DecimalField(max_digits=5, decimal_places=2)
    total_views = serializers.IntegerField()
    average_rating = serializers.DecimalField(max_digits=3, decimal_places=1)
    total_revenue = serializers.DecimalField(max_digits=10, decimal_places=2)


class QuizAnalyticsSerializer(serializers.Serializer):
    """
    Serializer for quiz analytics data
    """
    quiz_id = serializers.IntegerField()
    quiz_title = serializers.CharField()
    course_title = serializers.CharField()
    total_attempts = serializers.IntegerField()
    unique_students = serializers.IntegerField()
    average_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    pass_rate = serializers.DecimalField(max_digits=5, decimal_places=2)
    average_time_minutes = serializers.DecimalField(max_digits=8, decimal_places=2)


class StudentProgressSerializer(serializers.Serializer):
    """
    Serializer for individual student progress
    """
    student_id = serializers.IntegerField()
    student_name = serializers.CharField()
    student_email = serializers.CharField()
    course_title = serializers.CharField()
    enrollment_date = serializers.DateTimeField()
    progress_percentage = serializers.DecimalField(max_digits=5, decimal_places=2)
    sections_completed = serializers.IntegerField()
    total_sections = serializers.IntegerField()
    quizzes_passed = serializers.IntegerField()
    total_quizzes = serializers.IntegerField()
    total_time_spent_minutes = serializers.IntegerField()
    last_activity = serializers.DateTimeField()


# Bulk operations serializers
class BulkEnrollmentSerializer(serializers.Serializer):
    """
    Serializer for bulk student enrollment
    """
    course_id = serializers.IntegerField()
    student_emails = serializers.ListField(
        child=serializers.EmailField(),
        allow_empty=False
    )
    
    def validate_course_id(self, value):
        try:
            course = Course.objects.get(id=value)
            if course.teacher != self.context['request'].user:
                raise serializers.ValidationError("You can only enroll students in your own courses")
            return value
        except Course.DoesNotExist:
            raise serializers.ValidationError("Course not found")
    
    def validate_student_emails(self, value):
        valid_emails = []
        invalid_emails = []
        
        for email in value:
            try:
                user = User.objects.get(email=email, user_type='student')
                valid_emails.append(user)
            except User.DoesNotExist:
                invalid_emails.append(email)
        
        if invalid_emails:
            raise serializers.ValidationError(
                f"Invalid student emails: {', '.join(invalid_emails)}"
            )
        
        return valid_emails
    

class TeacherSerializer(serializers.ModelSerializer):
    pic = serializers.ImageField(source='profile_picture', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'date_joined', 'pic']


from .models import Review

class ReviewSerializer(serializers.ModelSerializer):
    user_name = serializers.ReadOnlyField(source='user.full_name')

    class Meta:
        model = Review
        fields = ['id', 'user', 'user_name', 'rating', 'comment', 'created_at']
        read_only_fields = ['user', 'created_at']
        
class Section_IscompleteSerializer(serializers.ModelSerializer):
    class Meta:
        model = SectionView
        fields = ['is_completed']
        

# serializers.py
from rest_framework import serializers
from .models import Notification

class NotificationCreateSerializer(serializers.ModelSerializer):
    student_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )
    
    class Meta:
        model = Notification
        fields = ['title', 'message', 'student_ids', 'course', 'notification_type']
        extra_kwargs = {
            'course': {'required': False},
            'notification_type': {'required': False}
        }
    
    def validate(self, attrs):
        if 'student_ids' in attrs and attrs.get('course'):
            raise serializers.ValidationError("Cannot specify both student_ids and course")
        return attrs

class NotificationSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source='sender.full_name', read_only=True)
    course_title = serializers.CharField(source='course.title', read_only=True, allow_null=True)
    
    class Meta:
        model = Notification
        fields = ['id', 'sender_name', 'course_title', 'title', 'message', 
                 'notification_type', 'is_read', 'created_at']