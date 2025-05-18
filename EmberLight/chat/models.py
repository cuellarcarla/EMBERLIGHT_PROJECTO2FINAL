from django.db import models
from login.models import User
from journal.models import JournalEntry

class ChatSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=100, default="New Chat")
    created_at = models.DateTimeField(auto_now_add=True)

class ChatLog(models.Model):
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='logs')
    message = models.TextField()
    response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    context_entries = models.ManyToManyField(JournalEntry, blank=True)