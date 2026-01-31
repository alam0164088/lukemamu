"""
ASGI config for myproject project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os
import django

# Django setup FIRST
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

# THEN import Django models/auth
import jwt
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

from attorney import routing

User = get_user_model()

@database_sync_to_async
def get_user_from_token(token):
    """Extract user from JWT token"""
    import logging
    logger = logging.getLogger(__name__)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('user_id')
        logger.debug("JWT decoded: user_id=%s payload=%s", user_id, payload)
        user = User.objects.get(id=user_id)
        logger.debug("User found: %s", user)
        return user
    except Exception as e:
        logger.exception("JWT decode failed: %s", e)
        return AnonymousUser()

class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        """Parse JWT from WebSocket headers"""
        import logging
        logger = logging.getLogger(__name__)
        
        headers = dict(scope.get('headers', []))
        auth_header = headers.get(b'authorization', b'').decode()
        logger.debug("Auth header: %s", auth_header)
        
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer '
            logger.debug("Token extracted: %s...", token[:50])
            scope['user'] = await get_user_from_token(token)
            logger.debug("User set in scope: %s", scope['user'])
        else:
            logger.debug("No Bearer token found")
            scope['user'] = AnonymousUser()
        
        await super().__call__(scope, receive, send)

application = ProtocolTypeRouter({
    'http': get_asgi_application(),
    'websocket': JWTAuthMiddleware(
        URLRouter(
            routing.websocket_urlpatterns
        )
    ),
})
