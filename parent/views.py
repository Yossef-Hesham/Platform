from django.shortcuts import render
from student.views import QuizResultsView
from teacher.models import QuizAttempt
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from account.models import User
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.db.models import Avg, Sum, Count, Q
from student.models import Course, Section

from rest_framework import permissions

class IsParent(permissions.BasePermission):
    def has_permission(self, request, view):    
        return bool(request.user and request.user.is_authenticated and request.user.is_parent)

    
class ParentQuizResultsView(APIView):
    """
    Very simple parent dashboard with course names and total scores
    """
    permission_classes = [IsParent]

    def get(self, request, child_id):
        try:
            parent = request.user
            child = get_object_or_404(User, id=child_id, user_type='student')
            
            if child.parent != parent:
                return Response({"error": "Permission denied"}, status=403)
            
            # Get enrolled courses
            enrolled_courses = Course.objects.filter(
                enrollments__student=child,
                enrollments__is_active=True
            ).order_by('title')
            
            course_data = []
            total_score = 0
            total_quizzes = 0
            
            for course in enrolled_courses:
                # Get all completed quiz attempts for this course
                attempts = QuizAttempt.objects.filter(
                    student=child,
                    quiz__section__course=course,
                    is_completed=True
                )
                
                course_score = attempts.aggregate(total=Sum('score'))['total'] or 0
                quiz_count = attempts.count()
                
                course_info = {
                    "course_name": course.title,
                    # "total_score": float(course_score),
                    "quizzes_completed": quiz_count,
                    "average_score": round(float(course_score / quiz_count), 2) if quiz_count > 0 else 0
                }
                
                course_data.append(course_info)
                total_score += course_score
                total_quizzes += quiz_count
            
            response_data = {
                "child": child.full_name or child.username,
                "courses": course_data,
                "summary": {
                    "total_courses": len(course_data),
                    "overall_total_score": float(total_score),
                    "total_quizzes_completed": total_quizzes,
                    "overall_average": round(float(total_score / total_quizzes), 2) if total_quizzes > 0 else 0
                }
            }
            
            return Response(response_data)
            
        except Exception as e:
            return Response({"error": str(e)}, status=500)


      

class ParentSectionsCompletionView(APIView):
    """
    Show parent how many sections their child completed in each course
    """
    permission_classes = [IsParent]

    def get(self, request, child_id):
        try:
            parent = request.user
            child = get_object_or_404(User, id=child_id, user_type='student')
            
            # Verify parent-child relationship
            if child.parent != parent:
                return Response(
                    {"error": "Permission denied - not your child"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get all courses the child is enrolled in
            enrolled_courses = Course.objects.filter(
                enrollments__student=child,
                enrollments__is_active=True
            ).order_by('title')
            
            course_data = []
            total_completed = 0
            total_sections = 0
            
            for course in enrolled_courses:
                # Use the existing total_sections field from the model
                total_course_sections = course.total_sections
                
                # Count completed sections (sections where child passed the quiz)
                completed_sections = Section.objects.filter(
                    course=course,
                    quiz__attempts__student=child,
                    quiz__attempts__is_completed=True,
                    quiz__attempts__is_passed=True
                ).distinct().count()
                
                course_info = {
                    "course_id": course.id,
                    "course_name": course.title,
                    "sections_completed": completed_sections,
                    "total_sections": total_course_sections,
                    "completion_percentage": round(
                        (completed_sections / total_course_sections * 100) if total_course_sections > 0 else 0, 
                        2
                    )
                }
                
                course_data.append(course_info)
                total_completed += completed_sections
                total_sections += total_course_sections
            
            # Calculate overall progress
            overall_percentage = round(
                (total_completed / total_sections * 100) if total_sections > 0 else 0, 
                2
            )
            
            response_data = {
                "child": {
                    "id": child.id,
                    "name": child.full_name or child.username,
                    "username": child.username
                },
                "courses": course_data,
                "overall_summary": {
                    "total_courses": len(course_data),
                    "total_sections_completed": total_completed,
                    "total_sections": total_sections,
                    "overall_completion_percentage": overall_percentage
                }
            }
            
            return Response(response_data)
            
        except User.DoesNotExist:
            return Response(
                {"error": "Child not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            print(f"Error in ParentSectionsCompletionView: {str(e)}")
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )