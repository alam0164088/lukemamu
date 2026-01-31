from django.db import models
from django.conf import settings

# Create your models here.

class ConsultationRequest(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_ACCEPTED = 'accepted'
    STATUS_DECLINED = 'declined'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_ACCEPTED, 'Accepted'),
        (STATUS_DECLINED, 'Declined'),
    ]

    sender = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='sent_consultations', on_delete=models.CASCADE)
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='received_consultations', on_delete=models.CASCADE)
    subject = models.CharField(max_length=255, blank=True)
    message = models.TextField(blank=True)

    # added: structured case details (JSON)
    case_details = models.JSONField(null=True, blank=True)

    status = models.CharField(max_length=32, default='pending')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    accepted_at = models.DateTimeField(null=True, blank=True)

    # add parent thread pointer
    parent = models.ForeignKey('self', null=True, blank=True, related_name='replies', on_delete=models.CASCADE)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.subject or 'Consult'} from {self.sender_id} to {self.receiver_id}"

class Message(models.Model):
    consultation = models.ForeignKey('ConsultationRequest', null=True, blank=True, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='received_messages', on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Message({self.pk}) from {self.sender_id} to {self.receiver_id}"
