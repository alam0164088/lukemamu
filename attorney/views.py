from django.shortcuts import render
from django.db.models import Q
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ConsultationRequest, Message
from .serializers import ConsultationSerializer, MessageSerializer, ConsultationCreateSerializer, ConsultationReplySerializer
import logging
from datetime import timedelta

logger = logging.getLogger(__name__)

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

        # If sender is attorney and they are sending the one-time offer/reply,
        # mark consultation as "offered" so the receiver can accept it.
        if getattr(request.user, "role", "") == "attorney":
            # prefer model constant if available
            consult.status = getattr(ConsultationRequest, "STATUS_OFFERED", "offered")

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
            "receiver": {"id": msg.receiver.id, "email": getattr(msg.receiver, "email",""), "full_name": getattr(msg.receiver, "full_name", "")},
            "subject": consult.subject,
            "description": case.get("description"),
            "location": case.get("location"),
            "budget": case.get("budget"),
            "message": msg.content,
            "is_read": msg.is_read,
            "created_at": msg.created_at.isoformat()
        }

        # broadcast via channels if configured (send flattened payload)
        socket_sent = False
        try:
            from asgiref.sync import async_to_sync
            from channels.layers import get_channel_layer
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"chat_{consultation_pk}",
                {
                    "type": "chat.message",
                    "message": resp
                }
            )
            socket_sent = True
        except Exception as e:
            import logging
            logging.getLogger(__name__).exception("channel send failed")

        # include socket delivery info in response for debugging/frontend
        resp["socket_sent"] = socket_sent
        resp["ws_group"] = f"chat_{consultation_pk}"
        return Response(resp, status=status.HTTP_201_CREATED)

class ConsultationAcceptView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            consult = ConsultationRequest.objects.get(pk=pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail":"Consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != consult.receiver and request.user != consult.sender:
            return Response({"detail": "Not allowed. Only the receiver or the request creator may accept this offer."}, status=status.HTTP_403_FORBIDDEN)

        consult.status = ConsultationRequest.STATUS_ACCEPTED
        consult.accepted_at = timezone.now()
        consult.save(update_fields=['status', 'accepted_at', 'updated_at'])

        accepted_by = {
            "id": request.user.id,
            "email": getattr(request.user, "email", None),
            "full_name": getattr(request.user, "full_name", None)
        }

        # notify via channels (optional)
        try:
            from asgiref.sync import async_to_sync
            from channels.layers import get_channel_layer
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"chat_{pk}",
                {
                    "type": "chat.accepted",
                    "message": {
                        "consultation": consult.id,
                        "status": consult.status,
                        "accepted_by": {
                            "id": request.user.id,
                            "email": getattr(request.user, "email", None),
                            "full_name": getattr(request.user, "full_name", None)
                        }
                    }
                }
            )
        except Exception:
            pass

        return Response({
            "detail": "Consultation accepted.",
            "accepted_by": accepted_by,
            "consultation": ConsultationSerializer(consult).data
        }, status=status.HTTP_200_OK)

class MessagesListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, consultation_pk):
        try:
            consult = ConsultationRequest.objects.get(pk=consultation_pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail": "Consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != consult.sender and request.user != consult.receiver:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)

        logger.debug("GET messages: consult=%s status=%s accepted_at=%s updated_at=%s", consult.id, consult.status, consult.accepted_at, consult.updated_at)

        # only return messages created at/after the accept time (use fallback and small grace window)
        if consult.status != ConsultationRequest.STATUS_ACCEPTED:
            logger.debug("Returning empty because status != accepted")
            return Response({"messages": []}, status=status.HTTP_200_OK)

        since = consult.accepted_at or consult.updated_at or consult.created_at
        # subtract 1 second to avoid clock-race where message and accept timestamps are equal
        since = since - timedelta(seconds=1)
        qs = Message.objects.filter(consultation=consult, created_at__gte=since).order_by('created_at')

        logger.debug("Messages returned count=%s", qs.count())
        # return simplified flattened messages (no nested consultation object)
        simple = []
        for m in qs:
            simple.append({
                "id": m.id,
                "consultation": m.consultation.id,
                "sender": {"id": m.sender.id, "email": getattr(m.sender, "email", ""), "full_name": getattr(m.sender, "full_name", "")},
                "receiver": {"id": m.receiver.id, "email": getattr(m.receiver, "email", ""), "full_name": getattr(m.receiver, "full_name", "")},
                "content": m.content,
                "is_read": m.is_read,
                "created_at": m.created_at.isoformat() if m.created_at else None
            })
        return Response(simple, status=status.HTTP_200_OK)

    def post(self, request, consultation_pk):
        try:
            consult = ConsultationRequest.objects.get(pk=consultation_pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail": "Consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != consult.sender and request.user != consult.receiver:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)

        # Only allow sending messages after the consultation has been accepted
        if consult.status != ConsultationRequest.STATUS_ACCEPTED:
            return Response({"detail": "Conversation not allowed until the consultation offer is accepted."}, status=status.HTTP_403_FORBIDDEN)

        serializer = MessageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # determine receiver (the other participant)
        receiver = consult.receiver if request.user.pk == consult.sender.pk else consult.sender

        # save message with explicit receiver
        msg = serializer.save(consultation=consult, sender=request.user, receiver=receiver)

        # prepare flattened payload
        case = consult.case_details or {}
        resp = {
            "id": msg.id,
            "consultation": consult.id,
            "sender": {"id": msg.sender.id, "email": getattr(msg.sender, "email", ""), "full_name": getattr(msg.sender, "full_name", "")},
            "receiver": {"id": msg.receiver.id, "email": getattr(msg.receiver, "email", ""), "full_name": getattr(msg.receiver, "full_name", "")},
            "subject": consult.subject,
            "description": case.get("description"),
            "location": case.get("location"),
            "budget": case.get("budget"),
            "message": msg.content,
            "is_read": msg.is_read,
            "created_at": msg.created_at.isoformat() if msg.created_at else None
        }

        # broadcast via channels if configured
        socket_sent = False
        try:
            from asgiref.sync import async_to_sync
            from channels.layers import get_channel_layer
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"chat_{consultation_pk}",
                {"type": "chat.message", "message": resp}
            )
            socket_sent = True
        except Exception:
            import logging
            logging.getLogger(__name__).exception("channel send failed")

        resp["socket_sent"] = socket_sent
        resp["ws_group"] = f"chat_{consultation_pk}"
        return Response(resp, status=status.HTTP_201_CREATED)

class MyConsultationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        received = []

        # Attorney view: return consultation-level items with latest reply flattened
        if getattr(user, "role", "") == "attorney":
            qs = ConsultationRequest.objects.filter(receiver=user).order_by('-updated_at')
            for c in qs:
                item = {
                    "id": c.id,
                    "sender": {"id": c.sender.id, "email": getattr(c.sender, "email", ""), "full_name": getattr(c.sender, "full_name", "")},
                    "receiver": {"id": c.receiver.id, "email": getattr(c.receiver, "email", ""), "full_name": getattr(c.receiver, "full_name", "")},
                    "subject": c.subject,
                    "message": c.message,
                    "case_details": c.case_details or {},
                    "status": c.status,
                    "is_read": c.is_read,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "updated_at": c.updated_at.isoformat() if c.updated_at else None
                }
                last_msg = Message.objects.filter(consultation=c).order_by('-created_at').first()
                if last_msg:
                    case = c.case_details or {}
                    item.update({
                        "description": case.get("description"),
                        "location": case.get("location"),
                        "budget": case.get("budget"),
                        "latest_reply": {
                            "id": last_msg.id,
                            "consultation": c.id,
                            "sender": {"id": last_msg.sender.id, "email": getattr(last_msg.sender, "email", ""), "full_name": getattr(last_msg.sender, "full_name", "")},
                            "receiver": {"id": last_msg.receiver.id, "email": getattr(last_msg.receiver, "email", ""), "full_name": getattr(last_msg.receiver, "full_name", "")},
                            "message": last_msg.content,
                            "is_read": last_msg.is_read,
                            "created_at": last_msg.created_at.isoformat() if last_msg.created_at else None
                        }
                    })
                received.append(item)

        # Normal user view: return flattened latest message per consultation (so no duplicates)
        else:
            consult_ids = Message.objects.filter(receiver=user).values_list('consultation', flat=True).distinct()
            for cid in consult_ids:
                m = Message.objects.filter(receiver=user, consultation_id=cid).order_by('-created_at').first()
                if not m:
                    continue
                consult = m.consultation
                case = consult.case_details or {}
                received.append({
                    "id": m.id,
                    "consultation": consult.id,
                    "sender": {"id": m.sender.id, "email": getattr(m.sender, "email", ""), "full_name": getattr(m.sender, "full_name", "")},
                    "receiver": {"id": m.receiver.id, "email": getattr(m.receiver, "email", ""), "full_name": getattr(m.receiver, "full_name", "")},
                    "subject": consult.subject,
                    "description": case.get("description"),
                    "location": case.get("location"),
                    "budget": case.get("budget"),
                    "message": m.content,
                    "is_read": m.is_read,
                    "created_at": m.created_at.isoformat() if m.created_at else None
                })

        return Response({"received": received}, status=status.HTTP_200_OK)