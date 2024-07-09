from django.contrib.auth.models import AbstractUser
from django.db import models
from enum import Enum
from django.utils import timezone
from datetime import timedelta

class UserRole(Enum):
    ADMIN = 'admin'
    MANAGER = 'manager'
    EMPLOYEE = 'employee'
    CLIENT = 'client'

class CustomUser(AbstractUser):
    role = models.CharField(
        max_length=20,
        choices=[(role.value, role.name) for role in UserRole],
        default=UserRole.CLIENT.value
    )
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    def __str__(self):
        return self.username


class EmailVerification(models.Model):
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=24)
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at