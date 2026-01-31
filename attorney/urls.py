# attorney/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from attorney import views
from .views import (
    ConsultationCreateView,
    ConsultationListView,
    ConsultationReplyView,
    ConsultationAcceptView,
    MessagesListCreateView,
    MyConsultationsView
)

router = DefaultRouter()
router.register(r'events', views.EventViewSet, basename='event')

urlpatterns = [
    path('api/attorney/', include(router.urls)),
    path('consultations/', ConsultationCreateView.as_view(), name='consultation-create'),
    path('consultations/me/', MyConsultationsView.as_view(), name='consultations-me'),
    path('consultations/<int:pk>/reply/', ConsultationReplyView.as_view(), name='consultation-reply'),
    path('consultations/<int:pk>/accept/', ConsultationAcceptView.as_view(), name='consultation-accept'),
    path('consultations/<int:consultation_pk>/messages/', MessagesListCreateView.as_view(), name='consultation-messages'),
]