from django.urls import re_path
from .consumers import ChatConsumer

websocket_urlpatterns = [
    re_path(r'ws/consultations/(?P<consultation_pk>\d+)/$', ChatConsumer.as_asgi()),
]