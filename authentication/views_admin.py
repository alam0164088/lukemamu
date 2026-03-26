# Admin Dashboard Views for User Management
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import logging

from .permissions import IsAdmin
from .serializers import SimpleUserProfileSerializer
from .models import Attorney

logger = logging.getLogger(__name__)
User = get_user_model()


@method_decorator(csrf_exempt, name='dispatch')
class GetUserProfileView(APIView):
    """
    GET: Retrieve a single user's profile by ID
    Admin can view any user, users can view their own profile
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id=None):
        """Get user profile by ID"""
        # If no user_id provided, return current user's profile
        if user_id is None:
            user = request.user
        else:
            # Only admin can view other users' profiles
            if request.user.role != 'admin' and request.user.id != int(user_id):
                return Response(
                    {"error": "Permission denied. You can only view your own profile."},
                    status=status.HTTP_403_FORBIDDEN
                )
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

        serializer = UserProfileSerializer(user, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class GetAllUsersView(APIView):
    """
    GET: Retrieve list of all users (role='user' only) with pagination (Admin only)
    Query params:
    - page: Page number (default: 1)
    - page_size: Items per page (default: 10, max: 100)
    - search: Search by email or full_name
    """
    permission_classes = [IsAdmin]  # Only admin can access

    def get(self, request):
        """Get paginated list of all users (regular users only, not attorneys)"""
        # Get query parameters
        page = request.query_params.get('page', 1)
        page_size = min(int(request.query_params.get('page_size', 10)), 100)
        search = request.query_params.get('search')

        # Build queryset - DEFAULT: only role='user'
        queryset = User.objects.filter(role='user').order_by('-created_at')

        # Apply search filter
        if search:
            queryset = queryset.filter(
                Q(email__icontains=search) | Q(full_name__icontains=search)
            )

        # Get total stats before pagination
        total_users = queryset.count()
        active_users = queryset.filter(is_email_verified=True).count()
        inactive_users = queryset.filter(is_email_verified=False).count()

        # Paginate
        paginator = Paginator(queryset, page_size)
        try:
            page_obj = paginator.page(page)
        except Exception as e:
            return Response(
                {"error": f"Invalid page: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = SimpleUserProfileSerializer(
            page_obj.object_list,
            many=True,
            context={"request": request}
        )

        return Response({
            "stats": {
                "total_users": total_users,
                "active_users": active_users,
                "inactive_users": inactive_users
            },
            "pagination": {
                "count": paginator.count,
                "total_pages": paginator.num_pages,
                "current_page": int(page),
                "page_size": page_size
            },
            "results": serializer.data
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class GetUsersByRoleView(APIView):
    """
    GET: Get all attorneys (role='attorney' only) with pagination (Admin only)
    Query params:
    - page: Page number (default: 1)
    - page_size: Items per page (default: 10, max: 100)
    - search: Search by email or full_name
    """
    permission_classes = [IsAdmin]

    def get(self, request):
        """Get paginated list of all attorneys only"""
        # Get query parameters
        page = request.query_params.get('page', 1)
        page_size = min(int(request.query_params.get('page_size', 10)), 100)
        search = request.query_params.get('search')

        # Build queryset - DEFAULT: only role='attorney'
        queryset = User.objects.filter(role='attorney').order_by('-created_at')

        # Apply search filter
        if search:
            queryset = queryset.filter(
                Q(email__icontains=search) | Q(full_name__icontains=search)
            )

        # Get total stats before pagination
        total_attorneys = queryset.count()
        active_attorneys = queryset.filter(is_email_verified=True).count()
        inactive_attorneys = queryset.filter(is_email_verified=False).count()

        # Paginate
        paginator = Paginator(queryset, page_size)
        try:
            page_obj = paginator.page(page)
        except Exception as e:
            return Response(
                {"error": f"Invalid page: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = SimpleUserProfileSerializer(
            page_obj.object_list,
            many=True,
            context={"request": request}
        )

        return Response({
            "stats": {
                "total_attorneys": total_attorneys,
                "active_attorneys": active_attorneys,
                "inactive_attorneys": inactive_attorneys
            },
            "pagination": {
                "count": paginator.count,
                "total_pages": paginator.num_pages,
                "current_page": int(page),
                "page_size": page_size
            },
            "results": serializer.data
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class EditAttorneyTierView(APIView):
    """
    PUT: Update attorney tier (Admin only)
    Request body: {"tier": "gold"}
    Tiers: bronze, silver, gold, platinum
    """
    permission_classes = [IsAdmin]

    def put(self, request, attorney_id):
        """Update attorney tier"""
        try:
            user = User.objects.get(id=attorney_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if user is attorney
        if user.role != 'attorney':
            return Response(
                {"error": f"User is not an attorney (role: {user.role})"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get or create attorney profile
        attorney_profile, created = Attorney.objects.get_or_create(user=user)

        # Get tier from request
        tier = request.data.get('tier')
        if not tier:
            return Response(
                {"error": "tier field is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate tier
        valid_tiers = ['one', 'two', 'three', 'four']
        if tier not in valid_tiers:
            return Response(
                {"error": f"Invalid tier. Must be one of: {', '.join(valid_tiers)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update tier
        attorney_profile.tier = tier
        attorney_profile.save()

        logger.info(f"Attorney tier updated: {user.email} -> {tier} by admin {request.user.email}")

        return Response({
            "message": "Attorney tier updated successfully",
            "user_id": attorney_id,
            "email": user.email,
            "full_name": user.full_name,
            "tier": attorney_profile.tier
        }, status=status.HTTP_200_OK)
