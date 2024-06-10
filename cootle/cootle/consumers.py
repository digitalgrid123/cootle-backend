import json
from channels.generic.websocket import AsyncWebsocketConsumer

class InvitationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = 'invitations'

        # Join group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        event_type = text_data_json.get('event_type', 'generic')

        # Send message to group
        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'invitation_message',
                'message': message,
                'event_type': event_type
            }
        )

    # Receive message from group
    async def invitation_message(self, event):
        message = event['message']
        event_type = event.get('event_type', 'generic')

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message,
            'event_type': event_type
        }))
