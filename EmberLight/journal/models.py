from django.db import models
from login.models import User

class JournalEntry(models.Model):
    MOOD_CHOICES = [
        ('feliz', '😊 Feliz'),
        ('neutral', '😐 Neutral'),
        ('triste', '😢 Triste'),
        ('enojado', '😠 Enojado'),
        ('ansioso', '😰 Ansioso'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    mood = models.CharField(max_length=10, choices=MOOD_CHOICES)
    text = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'date')
        ordering = ['-date']

    def __str__(self):
        return f"{self.user.username} - {self.date}: {self.mood}"