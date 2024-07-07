from django.contrib.auth.models import AbstractUser
from django.db import models
from enum import Enum

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
