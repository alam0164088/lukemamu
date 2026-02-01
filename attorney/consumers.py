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
    """Extract user from JWT token"""
    try:
        # ✓ Use JWT_SECRET, not SECRET_KEY
        secret = getattr(settings, 'JWT_SECRET', settings.SECRET_KEY)
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        user_id = payload.get('user_id')
        logger.debug("✓ JWT decoded user_id=%s", user_id)
        user = User.objects.get(id=user_id)
        logger.debug("✓ User found: id=%s", user.id)
        return user
    except User.DoesNotExist:
        logger.warning("✗ User not found for user_id=%s", user_id)
        return None
    except jwt.InvalidSignatureError:
        logger.warning("✗ JWT signature invalid - wrong secret key used")
        return None
    except jwt.DecodeError as e:
        logger.exception("✗ JWT decode error: %s", e)
        return None
    except Exception as e:
        logger.exception("✗ Token decode failed: %s", e)
        return None

@sync_to_async
def get_consultation_details(consultation_id):
    """Get consultation status and details"""
    try:
        from attorney.models import ConsultationRequest
        consultation = ConsultationRequest.objects.get(pk=consultation_id)
        return {
            'id': consultation.id,
            'status': consultation.status,
            'sender_id': consultation.sender_id,
            'receiver_id': consultation.receiver_id
        }
    except ConsultationRequest.DoesNotExist:
        logger.warning("✗ Consultation not found pk=%s", consultation_id)
        return None
    except Exception as e:
        logger.exception("✗ get_consultation_details failed: %s", e)
        return None

@sync_to_async
def get_receiver_id(consultation_id, sender_id):
    """Auto-detect receiver based on ConsultationRequest sender/receiver"""
    try:
        from attorney.models import ConsultationRequest
        consultation = ConsultationRequest.objects.get(pk=consultation_id)
        
        logger.debug("Consultation: sender_id=%s receiver_id=%s", 
                     consultation.sender_id, consultation.receiver_id)
        
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
        logger.exception("✗ Consultation not found pk=%s", consultation_id)
        return None
    except Exception as e:
        logger.exception("✗ get_receiver_id failed: %s", e)
        return None

@sync_to_async
def _save_message_with_receiver(consultation_id, sender_id, receiver_id, content):
    """Save message to database"""
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
        
        # ✓ Extract and validate token BEFORE accepting connection
        headers = dict(self.scope.get('headers', []))
        auth_header = headers.get(b'authorization', b'').decode()
        
        if not auth_header.startswith('Bearer '):
            logger.warning("✗ No Bearer token in Authorization header")
            await self.close(code=4001)
            return
        
        token = auth_header[7:].strip()
        user = await get_user_from_token(token)
        
        if not user:
            logger.warning("✗ Could not authenticate user from token")
            await self.close(code=4002)
            return
        
        self.user_id = user.id
        self.user = user
        
        # ✓ Now add to group and accept
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.debug("✓ WS ACCEPTED for user_id=%s", self.user_id)

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
        
        message_text = content.get('content', '').strip()
        if not message_text:
            await self.send_json({"error": "Message cannot be empty"})
            return
        
        sender_id = self.user_id
        
        # ✓ Get consultation status
        consultation = await get_consultation_details(self.consultation_id)
        if not consultation:
            await self.send_json({"error": "Consultation not found"})
            return
        
        # ✓ Check permission
        if sender_id != consultation['sender_id'] and sender_id != consultation['receiver_id']:
            await self.send_json({"error": "You don't have permission to access this consultation"})
            return
        
        # ✓ CHECK STATUS - যতক্ষণ accepted না হয়, কেউ message পাঠাতে পারবে না
        if consultation['status'] != 'accepted':
            is_attorney = sender_id == consultation['receiver_id']
            
            if is_attorney:
                await self.send_json({
                    "error": "Cannot send message. User has not yet accepted the consultation.",
                    "status": consultation['status'],
                    "message": "Wait for the user to accept your offer before messaging.",
                    "can_message": False
                })
            else:
                await self.send_json({
                    "error": "Consultation not accepted yet.",
                    "status": consultation['status'],
                    "message": "Please wait for the attorney's response.",
                    "can_message": False
                })
            return
        
        # ✓ Auto-detect receiver
        receiver_id = await get_receiver_id(self.consultation_id, sender_id)
        if not receiver_id:
            await self.send_json({"error": "Could not determine receiver"})
            return
        
        logger.debug("✓ Final validation: message=%s sender=%s receiver=%s", 
                     message_text, sender_id, receiver_id)
        
        # ✓ Send ACK
        await self.send_json({
            "ack": True,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "content": message_text
        })
        logger.debug("✓ ACK sent")
        
        # ✓ Save to DB
        await _save_message_with_receiver(self.consultation_id, sender_id, receiver_id, message_text)
        
        # ✓ Broadcast to group
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
        logger.debug("✓ CHAT_MESSAGE handler called")
        await self.send_json({
            "type": "message",
            "sender_id": event['message']['sender_id'],
            "receiver_id": event['message']['receiver_id'],
            "content": event['message']['content']
        })