from rest_framework import serializers
from .models import ChatSession, ChatLog
from journal.serializers import JournalEntrySerializer

class ChatLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatLog
        fields = ["id", "message", "response", "timestamp", "context_entries"]
        read_only_fields = ["id", "response", "timestamp"]

class ChatSessionSerializer(serializers.ModelSerializer):
    logs = ChatLogSerializer(many=True, read_only=True)
    
    class Meta:
        model = ChatSession
        fields = ["id", "title", "created_at", "logs"]
        read_only_fields = ["id", "created_at"]