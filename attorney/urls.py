# attorney/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ConsultationCreateView,
    ConsultationListView,
    ConsultationReplyView,
    ConsultationAcceptView,
    ConsultationRejectView,
    MessagesListCreateView,
    UserReplyMessagesView,
    MyConsultationsView,
    AttorneyProfileListView,
    EventViewSet,
    SimpleCreateRatingView,
)

router = DefaultRouter()
router.register(r'events', EventViewSet, basename='event')

urlpatterns = [
    path('', include(router.urls)),
    path('attorneys/', AttorneyProfileListView.as_view(), name='attorney-list'),

    # consultations list (GET) and create (POST)
    path('consultations/', ConsultationListView.as_view(), name='consultation-list'),
    path('consultations/create/', ConsultationCreateView.as_view(), name='consultation-create'),

    path('consultations/me/', MyConsultationsView.as_view(), name='consultations-me'),
    path('consultations/<int:pk>/reply/', ConsultationReplyView.as_view(), name='consultation-reply'),
    path('consultations/<int:pk>/accept/', ConsultationAcceptView.as_view(), name='consultation-accept'),
    path('consultations/<int:pk>/reject/', ConsultationRejectView.as_view(), name='consultation-reject'),
    path('consultations/<int:consultation_pk>/messages/', MessagesListCreateView.as_view(), name='consultation-messages'),
    path('consultations/reply-messages/', UserReplyMessagesView.as_view(), name='user-reply-messages'),
    path('attorneys/<int:attorney_id>/ratings/simple/', SimpleCreateRatingView.as_view(), name='attorney-simple-rating'),
]