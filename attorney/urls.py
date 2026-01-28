# attorney/urls.py
from django.urls import path
from .views import ConsultationCreateView, ConsultationListView, ConsultationReplyView

urlpatterns = [
    path('consultations/', ConsultationCreateView.as_view(), name='consultation-create'),  
    path('consultations/me/', ConsultationListView.as_view(), name='consultation-list'),  
    path('consultations/<int:pk>/reply/', ConsultationReplyView.as_view(), name='consultation-reply'),  # new
]