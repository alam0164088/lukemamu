from django.shortcuts import render
from django.db.models import Q
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ConsultationRequest, Message
from .serializers import ConsultationSerializer, MessageSerializer, ConsultationCreateSerializer, ConsultationReplySerializer

class ConsultationCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # আলাদা পরীক্ষা (temporary debugging)
        serializer = ConsultationCreateSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            print("SERIALIZER ERRORS:", serializer.errors)
            return Response(serializer.errors, status=400)

        obj = serializer.save()
        return Response(ConsultationSerializer(obj).data, status=201)

class ConsultationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # attorney: show requests sent TO the attorney (incoming)
        if getattr(user, 'role', '') == 'attorney':
            received_qs = ConsultationRequest.objects.filter(receiver=user).order_by('-created_at')
            return Response({"received": ConsultationSerializer(received_qs, many=True).data},
                            status=status.HTTP_200_OK)

        # normal user: show only items where this user is the receiver (offers from attorneys)
        received_qs = ConsultationRequest.objects.filter(receiver=user, sender__role='attorney').order_by('-created_at')
        return Response({"received": ConsultationSerializer(received_qs, many=True).data},
                        status=status.HTTP_200_OK)

class ConsultationReplyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        consultation_pk = kwargs.get('consultation_pk') or kwargs.get('pk')
        if not consultation_pk:
            return Response({"detail": "Missing consultation id in URL."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            consult = ConsultationRequest.objects.get(pk=consultation_pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail": "Consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != consult.sender and request.user != consult.receiver:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)

        # Prevent multiple replies from the attorney for the same consultation
        # If the current user is the attorney (receiver) and they've already replied,
        # return the existing reply instead of a 400 error.
        if getattr(request.user, "role", "") == "attorney":
            existing_msg = Message.objects.filter(consultation=consult, sender__role='attorney').order_by('-created_at').first()
            if existing_msg:
                case = consult.case_details or {}
                resp_existing = {
                    "id": existing_msg.id,
                    "consultation": consult.id,
                    "sender": {"id": existing_msg.sender.id, "email": getattr(existing_msg.sender, "email",""), "full_name": getattr(existing_msg.sender,"full_name","")},
                    "receiver": {"id": existing_msg.receiver.id, "email": getattr(existing_msg.receiver, "email",""), "full_name": getattr(existing_msg.receiver,"full_name","")},
                    "subject": consult.subject,
                    "description": case.get("description"),
                    "location": case.get("location"),
                    "budget": case.get("budget"),
                    "message": existing_msg.content,
                    "is_read": existing_msg.is_read,
                    "created_at": existing_msg.created_at.isoformat() if existing_msg.created_at else None,
                    "note": "reply_already_exists"
                }
                return Response(resp_existing, status=status.HTTP_200_OK)

        serializer = ConsultationReplySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # build case_details from either nested key, string, or flat fields
        incoming_case = data.get('case_details') or {}
        # if client sent flat keys, merge them
        for k in ('description', 'location', 'budget'):
            if k in request.data and request.data.get(k) is not None:
                incoming_case[k] = request.data.get(k)

        # merge into existing consultation case_details
        existing = consult.case_details or {}
        existing.update(incoming_case or {})
        consult.case_details = existing or None

        if 'subject' in data and data.get('subject') is not None:
            consult.subject = data['subject']
        consult.save()

        # create message
        message_text = data['message']
        receiver = consult.receiver if request.user.pk == consult.sender.pk else consult.sender
        msg = Message.objects.create(
            consultation=consult,
            sender=request.user,
            receiver=receiver,
            content=message_text
        )

        # flattened response (matches your desired shape)
        case = consult.case_details or {}
        resp = {
            "id": msg.id,
            "consultation": consult.id,
            "sender": {"id": msg.sender.id, "email": getattr(msg.sender, "email",""), "full_name": getattr(msg.sender,"full_name","")},
            "receiver": {"id": msg.receiver.id, "email": getattr(msg.receiver, "email",""), "full_name": getattr(msg.receiver,"full_name","")},
            "subject": consult.subject,
            "description": case.get("description"),
            "location": case.get("location"),
            "budget": case.get("budget"),
            "message": msg.content,
            "is_read": msg.is_read,
            "created_at": msg.created_at.isoformat()
        }

        return Response(resp, status=status.HTTP_201_CREATED)

class ConsultationAcceptView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            consult = ConsultationRequest.objects.get(pk=pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail":"Consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        # only receiver (client) can accept an offer sent to them
        if request.user != consult.receiver:
            return Response({"detail":"Not allowed."}, status=status.HTTP_403_FORBIDDEN)

        consult.status = ConsultationRequest.STATUS_ACCEPTED
        consult.save(update_fields=['status','updated_at'])
        # Optional: notify via channels (consumer will broadcast if implemented)
        return Response(ConsultationSerializer(consult).data, status=status.HTTP_200_OK)

class MessagesListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, consultation_pk):
        try:
            consult = ConsultationRequest.objects.get(pk=consultation_pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail": "Consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != consult.sender and request.user != consult.receiver:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)

        qs = Message.objects.filter(consultation=consult).order_by('created_at')
        return Response(MessageSerializer(qs, many=True).data, status=status.HTTP_200_OK)

    def post(self, request, consultation_pk):
        try:
            consult = ConsultationRequest.objects.get(pk=consultation_pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail": "Consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        # only participants can send
        if request.user != consult.sender and request.user != consult.receiver:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)

        # If sender is attorney, ensure they haven't replied to this consultation already
        if getattr(request.user, "role", "") == "attorney":
            if Message.objects.filter(consultation=consult, sender__role='attorney').exists():
                return Response({"detail": "You have already replied to this consultation."}, status=status.HTTP_400_BAD_REQUEST)

        # determine receiver: the other participant
        receiver = consult.receiver if request.user.pk == consult.sender.pk else consult.sender

        content = request.data.get('content')
        if not content:
            return Response({"content": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)

        # create message explicitly to ensure NOT NULL fields are set
        msg = Message.objects.create(
            consultation=consult,
            sender=request.user,
            receiver=receiver,
            content=content
        )

        # broadcast via channels if configured
        try:
            from asgiref.sync import async_to_sync
            from channels.layers import get_channel_layer
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"chat_{consultation_pk}",
                {
                    "type": "chat.message",
                    "message": MessageSerializer(msg).data
                }
            )
        except Exception:
            # ignore channel errors in case channels not configured
            pass

        return Response(MessageSerializer(msg).data, status=status.HTTP_201_CREATED)

class MyConsultationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # attorney: return consultation-level items only
        if getattr(user, "role", "") == "attorney":
            received_qs = ConsultationRequest.objects.filter(receiver=user).order_by('-updated_at')
            consultations = []
            for c in received_qs:
                consultations.append({
                    "id": c.id,
                    "sender": {
                        "id": c.sender.id,
                        "email": getattr(c.sender, "email", ""),
                        "full_name": getattr(c.sender, "full_name", "")
                    },
                    "receiver": {
                        "id": c.receiver.id,
                        "email": getattr(c.receiver, "email", ""),
                        "full_name": getattr(c.receiver, "full_name", "")
                    },
                    "subject": c.subject,
                    "message": c.message,
                    "status": c.status,
                    "is_read": c.is_read,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "updated_at": c.updated_at.isoformat() if c.updated_at else None,
                })
            return Response({"received": consultations}, status=status.HTTP_200_OK)

        # normal user: return message-level items only (flattened)
        msgs_qs = Message.objects.filter(receiver=user).order_by('-created_at')
        messages = []
        for m in msgs_qs:
            consult = m.consultation
            case = consult.case_details or {}
            messages.append({
                "id": m.id,
                "consultation": consult.id,
                "sender": {
                    "id": m.sender.id,
                    "email": getattr(m.sender, "email", ""),
                    "full_name": getattr(m.sender, "full_name", "")
                },
                "receiver": {
                    "id": m.receiver.id,
                    "email": getattr(m.receiver, "email", ""),
                    "full_name": getattr(m.receiver, "full_name", "")
                },
                "subject": consult.subject,
                "description": case.get("description"),
                "location": case.get("location"),
                "budget": case.get("budget"),
                "message": m.content,
                "is_read": m.is_read,
                "created_at": m.created_at.isoformat() if m.created_at else None
            })

        return Response({"received": messages}, status=status.HTTP_200_OK)