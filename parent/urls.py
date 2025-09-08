from django.urls import path
from .views import ParentQuizResultsView, ParentSectionsCompletionView



urlpatterns = [
    path('children/<int:child_id>/quiz-results/', ParentQuizResultsView.as_view(), name='parent-quiz-results'),
    path('children/<int:child_id>/sections-completion/', ParentSectionsCompletionView.as_view(), name='parent-sections-completion'),
]