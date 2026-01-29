import json
from channels.generic.websocket import AsyncJsonWebsocketConsumer

class ChatConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.consultation_id = self.scope['url_route']['kwargs']['consultation_pk']
        self.group_name = f"chat_{self.consultation_id}"
        # authentication: ensure user is authenticated (you may use JWT auth in scope)
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        # expecting {"content": "text"}
        message = content.get('content')
        user = self.scope.get('user')
        # simple validation omitted; for production enforce participant check
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.message",
                "message": {
                    "sender_id": getattr(user,'id',None),
                    "content": message,
                }
            }
        )

    async def chat_message(self, event):
        await self.send_json(event['message'])