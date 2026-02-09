from django.contrib import admin
from .models import ConsultationRequest, Message, Event, AttorneyRating

# Register your models here.
admin.site.register(ConsultationRequest)
admin.site.register(Message)
admin.site.register(Event)
admin.site.register(AttorneyRating)
