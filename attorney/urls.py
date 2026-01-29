# attorney/urls.py
from django.urls import path
from .views import ConsultationCreateView, ConsultationListView, ConsultationReplyView, ConsultationAcceptView, MessagesListCreateView, MyConsultationsView

urlpatterns = [
    path('consultations/', ConsultationCreateView.as_view(), name='consultation-create'),  
    path('consultations/me/', MyConsultationsView.as_view(), name='consultations-me'),  
    path('consultations/<int:pk>/reply/', ConsultationReplyView.as_view(), name='consultation-reply'),  # new
    path('consultations/<int:pk>/accept/', ConsultationAcceptView.as_view(), name='consultation-accept'),  # new
    path('consultations/<int:consultation_pk>/messages/', MessagesListCreateView.as_view(), name='consultation-messages'),  # new
]