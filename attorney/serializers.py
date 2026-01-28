from rest_framework import serializers
from .models import ConsultationRequest
from django.contrib.auth import get_user_model

User = get_user_model()

class ConsultationCreateSerializer(serializers.ModelSerializer):
    receiver_id = serializers.IntegerField(write_only=True)
    case_details = serializers.JSONField(required=False, allow_null=True)

    class Meta:
        model = ConsultationRequest
        fields = ['receiver_id', 'subject', 'message', 'case_details']

    def validate_receiver_id(self, value):
        try:
            user = User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Receiver not found.")
        # optional: role check
        if getattr(user, 'role', '') != 'attorney':
            raise serializers.ValidationError("Receiver is not an attorney.")
        return value

    def create(self, validated_data):
        sender = self.context['request'].user
        receiver = User.objects.get(id=validated_data.pop('receiver_id'))
        case_details = validated_data.pop('case_details', None)
        return ConsultationRequest.objects.create(
            sender=sender,
            receiver=receiver,
            case_details=case_details,
            **validated_data
        )

class ConsultationSerializer(serializers.ModelSerializer):
    sender = serializers.SerializerMethodField()
    receiver = serializers.SerializerMethodField()
    case_details = serializers.JSONField()

    class Meta:
        model = ConsultationRequest
        fields = ['id', 'sender', 'receiver', 'subject', 'message', 'case_details', 'status', 'is_read', 'created_at', 'updated_at']

    def get_sender(self, obj):
        return {
            'id': obj.sender.id,
            'email': getattr(obj.sender, 'email', ''),
            'full_name': getattr(obj.sender, 'full_name', '')
        }

    def get_receiver(self, obj):
        return {
            'id': obj.receiver.id,
            'email': getattr(obj.receiver, 'email', ''),
            'full_name': getattr(obj.receiver, 'full_name', '')
        }

class ConsultationReplySerializer(serializers.Serializer):
    subject = serializers.CharField(required=False, allow_blank=True)
    message = serializers.CharField(required=False, allow_blank=True)
    case_details = serializers.JSONField(required=False, allow_null=True)

    def validate(self, attrs):
        cd = attrs.get('case_details')
        if cd is not None and not isinstance(cd, dict):
            raise serializers.ValidationError("case_details must be an object.")
        return attrs