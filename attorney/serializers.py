from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ConsultationRequest, Message
from attorney.models import Event

User = get_user_model()

class UserMiniSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    email = serializers.EmailField()
    full_name = serializers.CharField(source='full_name', allow_blank=True)

class ConsultationSerializer(serializers.ModelSerializer):
    sender = serializers.SerializerMethodField()
    receiver = serializers.SerializerMethodField()

    class Meta:
        model = ConsultationRequest
        fields = [
            'id', 'sender', 'receiver', 'subject', 'message',
            'case_details', 'status', 'is_read', 'created_at', 'updated_at'
        ]

    def get_sender(self, obj):
        u = obj.sender
        return {'id': u.id, 'email': getattr(u, 'email', ''), 'full_name': getattr(u, 'full_name', '')}

    def get_receiver(self, obj):
        u = obj.receiver
        return {'id': u.id, 'email': getattr(u, 'email', ''), 'full_name': getattr(u, 'full_name', '')}

class ConsultationCreateSerializer(serializers.ModelSerializer):
    receiver_id = serializers.IntegerField(write_only=True)
    case_details = serializers.JSONField(required=False, allow_null=True)
    message = serializers.CharField(required=False, allow_blank=True)  # optional

    class Meta:
        model = ConsultationRequest
        fields = ['receiver_id', 'subject', 'message', 'case_details']

    def validate_receiver_id(self, value):
        try:
            User.objects.get(pk=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Receiver not found.")
        return value

    def create(self, validated_data):
        request = self.context.get('request')
        sender = request.user
        receiver_id = validated_data.pop('receiver_id')
        receiver = User.objects.get(pk=receiver_id)
        case_details = validated_data.pop('case_details', None) or {}  # default to empty dict
        message_text = validated_data.pop('message', '')  # default empty if missing
        subject = validated_data.get('subject', '')
        return ConsultationRequest.objects.create(
            sender=sender,
            receiver=receiver,
            subject=subject,
            message=message_text,
            case_details=case_details
        )

class MessageSerializer(serializers.ModelSerializer):
    consultation = ConsultationSerializer(read_only=True)  # include full consultation
    sender = serializers.SerializerMethodField()
    receiver = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = ['id', 'consultation', 'sender', 'receiver', 'content', 'is_read', 'created_at']

    def get_sender(self, obj):
        u = obj.sender
        return {'id': u.id, 'email': getattr(u, 'email', ''), 'full_name': getattr(u, 'full_name', '')}

    def get_receiver(self, obj):
        u = obj.receiver
        return {'id': u.id, 'email': getattr(u, 'email', ''), 'full_name': getattr(u, 'full_name', '')}

class ConsultationReplySerializer(serializers.Serializer):
    message = serializers.CharField(required=True, allow_blank=False)
    subject = serializers.CharField(required=False, allow_blank=True)            # optional
    # accept either object or string (string -> treated as description)
    case_details = serializers.JSONField(required=False, allow_null=True)

    def validate_case_details(self, value):
        # if client sent a plain string, convert to dict {description: <string>}
        if isinstance(value, str):
            return {"description": value}
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        raise serializers.ValidationError("case_details must be an object or a string")

    def create(self, validated_data):
        return validated_data

class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = ['id', 'title', 'description', 'date', 'time', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

from attorney.models import ConsultationRequest

# Example of how to use the filter in the shell
# sender_id = 23 (token payload)
# print(ConsultationRequest.objects.filter(sender_id=23).order_by('-created_at').values('id','sender_id','receiver_id','subject','message')[:10])