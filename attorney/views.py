from django.shortcuts import render
from django.db.models import Q
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.decorators import action
from .models import ConsultationRequest, Message
from .serializers import ConsultationSerializer, MessageSerializer, ConsultationCreateSerializer, ConsultationReplySerializer
from attorney.models import Event
from attorney.serializers import EventSerializer
import logging
from datetime import timedelta, datetime, date
from django.db import models
from django.conf import settings
from django.db.models import Avg, Count
from decimal import Decimal, InvalidOperation

User = get_user_model()

logger = logging.getLogger(__name__)

def _has_field(model, field_name: str) -> bool:
    try:
        model._meta.get_field(field_name)
        return True
    except Exception:
        return False

def _iter_one_to_one_related(u):
    for rel in getattr(u._meta, "related_objects", []):
        if getattr(rel, "one_to_one", False):
            try:
                related_obj = getattr(u, rel.get_accessor_name(), None)
                if related_obj:
                    yield related_obj
            except Exception:
                continue

def _pick_attorney_obj(u):
    # prefer direct 'profile' then 'attorney_profile', otherwise pick any one-to-one
    for name in ("profile", "attorney_profile", "attorney", "attorney_details", "attorneyprofile"):
        obj = getattr(u, name, None)
        if obj:
            return obj
    # fallback: choose any one-to-one related object that looks like an attorney/profile
    for ro in _iter_one_to_one_related(u):
        if any(hasattr(ro, a) for a in ("designation", "area_of_law", "profile_image", "image", "avatar", "photo")):
            return ro
    return None

def _extract_attorney_data(u):
    fields = [
        "designation", "area_of_law", "bar_license_number",
        "bio", "languages", "experience", "response_time"
    ]
    data = {}
    # 1) user model এ থাকলে নাও
    for f in fields:
        val = getattr(u, f, None)
        if val is not None:
            data[f] = val

    # 2) related profile এ থাকলে নাও
    attorney_obj = _pick_attorney_obj(u)
    if attorney_obj:
        for f in fields:
            val = getattr(attorney_obj, f, None)
            if val is not None:
                data[f] = val

    return data or None

def _get_profile_image(u, request=None):
    # candidates: user, all one-to-one related objects (profile/attorney)
    candidates = [u] + list(_iter_one_to_one_related(u))
    # ensure attorney/profile candidate appears early
    att = _pick_attorney_obj(u)
    if att and att not in candidates:
        candidates.append(att)

    for obj in candidates:
        if not obj:
            continue
        # common field names first
        for field in ("profile_image", "avatar", "image", "photo", "profile_picture", "picture", "image_url"):
            val = getattr(obj, field, None)
            if val:
                try:
                    if hasattr(val, "url"):
                        return request.build_absolute_uri(val.url) if request else val.url
                    return str(val)
                except Exception:
                    return str(val)
        # fallback: any ImageField/FileField on the object
        for f in getattr(obj, "_meta", []).fields if hasattr(obj, "_meta") else []:
            if isinstance(f, (models.ImageField, models.FileField)):
                val = getattr(obj, f.name, None)
                if val:
                    try:
                        if hasattr(val, "url"):
                            return request.build_absolute_uri(val.url) if request else val.url
                        return str(val)
                    except Exception:
                        return str(val)

    # final fallback: serve default profile image (so frontend always gets URL)
    try:
        default_path = settings.MEDIA_URL.rstrip('/') + '/profile_images/default_profile.png'
        return request.build_absolute_uri(default_path) if request else default_path
    except Exception:
        return None

# added: minimal serializer for nested sender/receiver used by consultations endpoints
def _serialize_user_min(u, request=None):
    if u is None:
        return None
    return {
        "id": getattr(u, "id", None),
        "email": getattr(u, "email", None),
        "full_name": getattr(u, "full_name", f"{getattr(u,'first_name','')}".strip()),
        "profile_image": _get_profile_image(u, request),
    }

def _serialize_user(u, request=None):
    exclude = {
        "password", "user_permissions", "groups", "is_superuser",
        "last_login", "email_user", "get_session_auth_hash"
    }
    data = {}
    # use only concrete fields (no reverse relations)
    for f in u._meta.fields:
        name = f.name
        if name in exclude:
            continue

        val = getattr(u, name, None)

        # handle relations -> use id
        if isinstance(f, (models.ForeignKey, models.OneToOneField)):
            data[name] = getattr(val, "id", None)
            continue

        if isinstance(val, (datetime, date)):
            val = val.isoformat()

        # build absolute URL for profile_image if exists
        if name == "profile_image" and val:
            try:
                data[name] = request.build_absolute_uri(val.url) if request else val.url
                continue
            except Exception:
                pass

        data[name] = val

    data["profile_image"] = _get_profile_image(u, request)
    data["attorney"] = _extract_attorney_data(u)
    return data

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
        # update the existing reply with the new message instead of returning the old one.
        if getattr(request.user, "role", "") == "attorney":
            existing_msg = Message.objects.filter(consultation=consult, sender__role='attorney').order_by('-created_at').first()
            if existing_msg:
                # accept new content from request (use serializer validated data below)
                # mark we will update in-place; do not early-return here
                will_update_existing = True
            else:
                will_update_existing = False
        else:
            will_update_existing = False

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

        # create or update message
        message_text = data['message']
        receiver = consult.receiver if request.user.pk == consult.sender.pk else consult.sender
        if locals().get("will_update_existing"):
            # update previous attorney reply
            existing_msg.content = message_text
            existing_msg.is_read = False
            existing_msg.save()
            msg = existing_msg
        else:
            msg = Message.objects.create(
                consultation=consult,
                sender=request.user,
                receiver=receiver,
                content=message_text
            )

        # flattened response (matches your desired shape)
        case = consult.case_details or {}
        if isinstance(case, dict):
            case_details_val = case.get("description") or case.get("case_details") or ""
        else:
            case_details_val = str(case)

        resp = {
            "id": msg.id,
            "consultation": consult.id,
            "sender": {"id": msg.sender.id, "email": getattr(msg.sender, "email",""), "full_name": getattr(msg.sender,"full_name","")},
            "receiver": {"id": msg.receiver.id, "email": getattr(msg.receiver, "email",""), "full_name": getattr(msg.receiver, "full_name", "")},
            "subject": consult.subject,
            "case_details": case_details_val,
            "location": (case or {}).get("location") if isinstance(case, dict) else None,
            "budget": (case or {}).get("budget") if isinstance(case, dict) else None,
            "message": msg.content,
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
            "description": case.get("description") if isinstance(case, dict) else None,
            "location": case.get("location") if isinstance(case, dict) else None,
            "budget": case.get("budget") if isinstance(case, dict) else None,
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

class UserReplyMessagesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if str(getattr(request.user, "role", "")).lower() == "attorney":
            return Response({"detail": "Only users can fetch reply messages."}, status=status.HTTP_403_FORBIDDEN)

        qs = Message.objects.filter(
            Q(receiver=request.user) | Q(consultation__receiver=request.user)
        ).exclude(
            Q(sender__role__iexact="bot") |
            Q(sender__username__icontains="bot") |
            Q(sender__email__icontains="bot")
        ).select_related("consultation", "sender", "receiver").order_by("created_at")

        replies = []
        for m in qs:
            consult = m.consultation
            case = consult.case_details if consult else {}
            replies.append({
                "id": m.id,
                "consultation": consult.id if consult else None,
                "sender": {
                    "id": m.sender.id,
                    "email": getattr(m.sender, "email", ""),
                    "full_name": getattr(m.sender, "full_name", ""),
                    "profile_image": _get_profile_image(m.sender, request)
                },
                "receiver": {
                    "id": m.receiver.id,
                    "email": getattr(m.receiver, "email", ""),
                    "full_name": getattr(m.receiver, "full_name", ""),
                    "profile_image": _get_profile_image(m.receiver, request)
                },
                "subject": getattr(consult, "subject", None),
                "description": case.get("description") if isinstance(case, dict) else None,
                "location": case.get("location") if isinstance(case, dict) else None,
                "budget": case.get("budget") if isinstance(case, dict) else None,
                "message": m.content,
                "is_read": m.is_read,
                "created_at": m.created_at.isoformat() if m.created_at else None
            })

        return Response(replies, status=status.HTTP_200_OK)

def _get_attr(obj, names):
    for n in names:
        val = getattr(obj, n, None)
        if val is not None:
            return val
    return None

def _get_consultations_for_attorney(user):
    """
    Find consultations that are addressed to the given user by checking
    all FK fields on ConsultationRequest that point to the User model.
    Returns a queryset (distinct).
    """
    from django.db.models import Q

    fk_names = []
    for f in ConsultationRequest._meta.fields:
        try:
            if getattr(f, "remote_field", None) and getattr(f.remote_field, "model", None) is User:
                fk_names.append(f.name)
        except Exception:
            continue

    if not fk_names:
        return ConsultationRequest.objects.none()

    q = Q()
    for name in fk_names:
        q |= Q(**{name: user})

    return ConsultationRequest.objects.filter(q).distinct()

class MyConsultationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # robust attorney detection
        try:
            groups = list(user.groups.values_list("name", flat=True)) if hasattr(user, "groups") else []
        except Exception:
            groups = []

        is_attorney = (
            str(getattr(user, "role", "")).strip().lower() == "attorney"
            or bool(getattr(user, "is_attorney", False))
            or any(g.lower() == "attorney" for g in groups)
            or bool(getattr(user, "is_staff", False) and "attorney" in str(getattr(user, "role", "")).lower())
        )

        # --- CHANGED: when user is an attorney, return all consultation requests that users sent to this attorney
        if is_attorney:
            # use helper to find all FK fields that reference User and filter those consultations for this user
            # but exclude offers that were created by other attorneys (keep only user-originated requests)
            received_qs = (
                _get_consultations_for_attorney(user)
                .exclude(sender__role='attorney')   # keep only requests sent by non-attorney users
                .select_related("sender", "receiver")
                .order_by("-created_at")
            )
        else:
            # normal user: show offers from attorneys to this user
            received_qs = ConsultationRequest.objects.filter(receiver=user, sender__role='attorney').select_related("sender","receiver").order_by('-created_at')

        def _user_min(u):
            if not u:
                return None
            # always return an absolute profile image URL (fallback to default)
            img = _get_profile_image(u, request)
            return {
                "id": getattr(u, "id", None),
                "email": getattr(u, "email", "") or "",
                "full_name": getattr(u, "full_name", "") or "",
                "profile_image": img
            }

        out = []
        for c in received_qs:
            # hide latest_reply for this endpoint (always null)
            latest_reply = None

            out.append({
                "id": getattr(c, "id", None),
                "sender": _user_min(getattr(c, "sender", None)),
                "receiver": _user_min(getattr(c, "receiver", None)),
                "subject": getattr(c, "subject", None),
                "message": getattr(c, "message", None) or getattr(c, "text", None) or None,
                "status": getattr(c, "status", None),
                "created_at": getattr(c, "created_at", None).isoformat() if getattr(c, "created_at", None) else None,
                "updated_at": getattr(c, "updated_at", None).isoformat() if getattr(c, "updated_at", None) else None,
                "latest_reply": None
            })

        return Response({
            "received": out,
            "sent": [],
            "is_attorney": is_attorney
        }, status=status.HTTP_200_OK)

class EventViewSet(viewsets.ModelViewSet):
    """Event API — Create, Read, Update, Delete events"""
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Get only current user's events"""        
        import os
        
        User = get_user_model()
        u = User.objects.get(id=37)
        print("User fields:", [f.name for f in u._meta.fields])
        
        # check common image field names on user
        for name in ("profile_image","avatar","image","photo","profile_picture","picture","image_url"):
            v = getattr(u, name, None)
            print(name, "=>", v, "has_url:", hasattr(v, "url") if v else None)
        
        # inspect one-to-one related objects
        for rel in u._meta.related_objects:
            try:
                acc = rel.get_accessor_name()
                ro = getattr(u, acc, None)
                print("related:", acc, "obj:", bool(ro))
                if ro:
                    for f in ro._meta.fields:
                        if f.get_internal_type() in ("ImageField","FileField"):
                            val = getattr(ro, f.name, None)
                            print("  ", f.name, "=>", val, "has_url:", hasattr(val,"url") if val else None)
                            if val and hasattr(val, "path"):
                                print("   path exists:", os.path.exists(val.path))
            except Exception as e:
                print("related inspect error", e)
        
        print("MEDIA_ROOT:", settings.MEDIA_ROOT, "MEDIA_URL:", settings.MEDIA_URL)
        return Event.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        """Create event for current user"""
        serializer.save(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def my_events(self, request):
        """Get all events for current user"""
        events = self.get_queryset()
        serializer = self.get_serializer(events, many=True)
        return Response({
            'count': events.count(),
            'events': serializer.data
        })
    
    @action(detail=False, methods=['get'])
    def upcoming_events(self, request):
        """Get upcoming events (from today onwards)"""
        events = self.get_queryset().filter(date__gte=date.today()).order_by('date', 'time')
        serializer = self.get_serializer(events, many=True)
        return Response(serializer.data)

class AttorneyProfileListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = User.objects.all()

        if _has_field(User, "role"):
            qs = qs.filter(role="attorney")
        elif _has_field(User, "user_type"):
            qs = qs.filter(user_type="attorney")
        elif _has_field(User, "is_attorney"):
            qs = qs.filter(is_attorney=True)
        elif _has_field(User, "is_staff"):
            qs = qs.filter(is_staff=True)

        # collect ratings for these attorneys
        from .models import AttorneyRating
        ratings_qs = AttorneyRating.objects.filter(attorney__in=qs).values('attorney').annotate(
            avg_rating=Avg('rating'), count=Count('id')
        )
        rating_map = {
            r['attorney']: {
                "average": round(float(r['avg_rating']), 2) if r['avg_rating'] is not None else None,
                "count": r['count']
            } for r in ratings_qs
        }

        data = []
        for u in qs:
            ud = _serialize_user(u, request)
            ud['rating'] = rating_map.get(u.id, {"average": None, "count": 0})
            data.append(ud)

        return Response(data, status=status.HTTP_200_OK)

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

from .models import AttorneyRating
from .serializers import SimpleRatingSerializer

User = get_user_model()

class SimpleCreateRatingView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, attorney_id, *args, **kwargs):
        if getattr(request.user, "role", "").lower() == "attorney":
            return Response({"detail": "Attorneys cannot submit this rating."}, status=status.HTTP_403_FORBIDDEN)

        attorney = get_object_or_404(User, pk=attorney_id, role="attorney")

        # accept decimal input like 4.5, "4.5", 4
        try:
            rating_raw = request.data.get("rating", None)
            rating_val = Decimal(str(rating_raw))
        except (InvalidOperation, TypeError, ValueError):
            return Response({"detail": "Invalid rating value."}, status=status.HTTP_400_BAD_REQUEST)

        # normalize to one decimal place
        rating_val = rating_val.quantize(Decimal('0.1'))

        if rating_val < Decimal('1.0') or rating_val > Decimal('5.0'):
            return Response({"detail": "rating must be between 1.0 and 5.0"}, status=status.HTTP_400_BAD_REQUEST)

        obj, created = AttorneyRating.objects.update_or_create(
            attorney=attorney,
            rater=request.user,
            defaults={"rating": rating_val}
        )

        serializer = SimpleRatingSerializer(obj, context={"request": request})
        return Response(serializer.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)