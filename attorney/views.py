from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import ConsultationCreateSerializer, ConsultationSerializer, ConsultationReplySerializer
from .models import ConsultationRequest

class ConsultationCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ConsultationCreateSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            consult = serializer.save()
            return Response(ConsultationSerializer(consult).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ConsultationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # attorney: show only items the attorney SENT (their offers)
        if getattr(user, 'role', '') == 'attorney':
            sent_qs = ConsultationRequest.objects.filter(sender=user).order_by('-created_at')
            return Response({"sent": ConsultationSerializer(sent_qs, many=True).data},
                            status=status.HTTP_200_OK)

        # normal user: show only offers sent to this user BY attorneys
        received_qs = ConsultationRequest.objects.filter(receiver=user, sender__role='attorney').order_by('-created_at')
        return Response({"received": ConsultationSerializer(received_qs, many=True).data},
                        status=status.HTTP_200_OK)

class ConsultationReplyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            original = ConsultationRequest.objects.get(pk=pk)
        except ConsultationRequest.DoesNotExist:
            return Response({"detail": "Original consultation not found."}, status=status.HTTP_404_NOT_FOUND)

        # only the original receiver (attorney) may reply
        if request.user != original.receiver:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)

        serializer = ConsultationReplySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        subject = data.get('subject') or f"Re: {original.subject or 'Consultation'}"
        message = data.get('message', '')
        case_details = data.get('case_details')

        # create reply as a new ConsultationRequest (sender=attorney, receiver=original.sender)
        reply = ConsultationRequest.objects.create(
            sender=request.user,
            receiver=original.sender,
            subject=subject,
            message=message,
            case_details=case_details
        )

        # mark original as read
        original.is_read = True
        original.save(update_fields=['is_read'])

        return Response(ConsultationSerializer(reply).data, status=status.HTTP_201_CREATED)
