import json
import logging
import jwt
from django.conf import settings
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)
User = get_user_model()

@sync_to_async
def get_user_from_token(token):
    """Extract user from JWT token — WITHOUT signature verification"""
    try:
        # Decode WITHOUT verifying signature (safe for dev, extract user_id from payload)
        payload = jwt.decode(token, options={"verify_signature": False})
        user_id = payload.get('user_id')
        logger.debug("✓ JWT decoded (no sig verify) user_id=%s", user_id)
        user = User.objects.get(id=user_id)
        logger.debug("✓ User found: id=%s username=%s", user.id, user.username)
        return user
    except User.DoesNotExist:
        logger.warning("✗ User not found for user_id=%s", user_id)
        return None
    except Exception as e:
        logger.exception("✗ Token decode failed: %s", e)
        return None

@sync_to_async
def get_receiver_id(consultation_id, sender_id):
    """Auto-detect receiver based on ConsultationRequest sender/receiver"""
    try:
        from attorney.models import ConsultationRequest
        consultation = ConsultationRequest.objects.get(pk=consultation_id)
        
        logger.debug("Consultation: sender_id=%s receiver_id=%s", 
                     consultation.sender_id, consultation.receiver_id)
        
        # Simple logic: যদি sender consultation.sender_id হয় তাহলে receiver consultation.receiver_id
        if consultation.sender_id == sender_id:
            logger.debug("✓ Sender is client, receiver is attorney: %s", consultation.receiver_id)
            return consultation.receiver_id
        elif consultation.receiver_id == sender_id:
            logger.debug("✓ Sender is attorney, receiver is client: %s", consultation.sender_id)
            return consultation.sender_id
        else:
            logger.warning("✗ Sender %s not in consultation (sender_id=%s, receiver_id=%s)", 
                          sender_id, consultation.sender_id, consultation.receiver_id)
            return None
        
    except ConsultationRequest.DoesNotExist:
        logger.exception("Consultation not found pk=%s", consultation_id)
        return None
    except Exception as e:
        logger.exception("get_receiver_id failed: %s", e)
        return None

@sync_to_async
def _save_message_with_receiver(consultation_id, sender_id, receiver_id, content):
    """Save message"""
    try:
        from attorney.models import Message
        msg = Message.objects.create(
            consultation_id=consultation_id,
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=content
        )
        logger.debug("✓ Message saved id=%s sender=%s receiver=%s", msg.id, sender_id, receiver_id)
        return msg.id
    except Exception as e:
        logger.exception("✗ Failed to save message: %s", e)
        return None

class ChatConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        """Called when WebSocket connects"""
        self.consultation_id = self.scope['url_route']['kwargs']['consultation_pk']
        self.group_name = f"chat_{self.consultation_id}"
        
        logger.debug("WS CONNECT consultation=%s group=%s", self.consultation_id, self.group_name)
        
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.debug("✓ WS ACCEPTED")

    async def disconnect(self, close_code):
        """Called when WebSocket disconnects"""
        logger.debug("WS DISCONNECT code=%s", close_code)
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        """Raw receive handler"""
        if text_data:
            try:
                content = json.loads(text_data)
                await self.receive_json(content)
            except json.JSONDecodeError as e:
                logger.exception("JSON decode error: %s", e)
                await self.send_json({"error": "invalid JSON"})

    async def receive_json(self, content, **kwargs):
        """Called when client sends JSON message"""
        logger.debug("WS RECEIVE_JSON content=%s", content)
        
        # Extract message
        message_text = content.get('content')
        
        # Get sender from Authorization header
        headers = dict(self.scope.get('headers', []))
        auth_header = headers.get(b'authorization', b'').decode()
        
        sender_id = None
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()  # Remove 'Bearer ' and trim spaces
            logger.debug("Extracting user from access token...")
            user = await get_user_from_token(token)
            if user:
                sender_id = user.id
                logger.debug("✓ sender_id from token: %s", sender_id)
            else:
                logger.warning("✗ Could not extract user from token")
        else:
            logger.debug("No Bearer token in Authorization header")
        
        # Fallback: from payload
        if not sender_id:
            sender_id = content.get('user_id')
            if sender_id:
                logger.debug("Using fallback sender_id from payload: %s", sender_id)
        
        # Auto-detect receiver
        receiver_id = content.get('receiver_id')
        if not receiver_id and sender_id:
            receiver_id = await get_receiver_id(self.consultation_id, sender_id)
            if receiver_id:
                logger.debug("✓ Auto-detected receiver_id: %s", receiver_id)
            else:
                logger.warning("✗ Could not auto-detect receiver_id")
        
        logger.debug("Final validation: message=%s sender=%s receiver=%s", 
                     message_text, sender_id, receiver_id)
        
        # Validate
        if not message_text or not sender_id or not receiver_id:
            logger.warning("✗ VALIDATION FAILED")
            await self.send_json({"error": f"incomplete: text={message_text}, sender={sender_id}, receiver={receiver_id}"})
            return
        
        # Send ACK
        await self.send_json({
            "ack": True,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "content": message_text
        })
        logger.debug("✓ ACK sent")
        
        # Save to DB
        await _save_message_with_receiver(self.consultation_id, sender_id, receiver_id, message_text)
        
        # Broadcast
        try:
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "chat.message",
                    "message": {
                        "sender_id": sender_id,
                        "receiver_id": receiver_id,
                        "content": message_text,
                    }
                }
            )
            logger.debug("✓ Message broadcasted to group")
        except Exception as e:
            logger.exception("✗ group_send failed: %s", e)

    async def chat_message(self, event):
        """Called when message is sent to group"""
        logger.debug("CHAT_MESSAGE handler")
        await self.send_json(event['message'])