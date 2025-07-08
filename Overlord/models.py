from django.db import models
from django.contrib.auth.models import User

class EVEToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    character_id = models.IntegerField()
    character_name = models.CharField(max_length=255)
    access_token = models.TextField()
    refresh_token = models.TextField()
    expires_at = models.DateTimeField()
    scopes = models.TextField()

    def __str__(self):
        return f"{self.character_name} ({self.character_id})"