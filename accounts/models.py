from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from accounts.manager import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ("admin", "Admin"),
        ("agent", "Agent"),
        ("associate", "Associate"),
    )

    email = models.EmailField(unique=True)
    name = models.CharField(max_length=70, default=None)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    profile_image = models.ImageField(
        upload_to="users/profile/",
        null=True,
        blank=True,
        default="users/profile/default.png",
    )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email


class Task(models.Model):

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    agent = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="agent_tasks"
    )

    associate = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="associate_tasks"
    )

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending")

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class TaskHistory(models.Model):
    task = models.ForeignKey(
        Task,
        on_delete=models.CASCADE,
        related_name='updates'
    )

    updated_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )

    description = models.TextField()   # what associate spoke / updated
    status = models.CharField(max_length=20)
    updated_at = models.DateTimeField(auto_now_add=True)
