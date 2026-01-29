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
    INTEREST_LEVEL_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
    ]
    PURCHASE_TIMELINE_CHOICES = [
        ("immediate", "Immediate"),
        ("1-3", "1–3 Months"),
        ("3-6", "3–6 Months"),
        ("enquiry", "Just Enquiry"),
    ]
    PROPERTY_TYPE_CHOICES = [
        ("plot", "Plot"),
        ("flat", "Flat"),
        ("villa", "Villa"),
        ("commercial", "Commercial"),
    ]
    name = models.CharField(max_length=100)
    email = models.EmailField(blank=True, default="")
    phone = models.CharField(max_length=20,default="")
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    agent = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="agent_tasks", null=True,
    blank=True
    )

    associate = models.ForeignKey(
    User,
    on_delete=models.CASCADE,
    related_name="associate_tasks",
    null=True,   # allow NULL in database
    blank=True   # allow empty in forms
    )
    status = models.CharField(
     max_length=20, choices=STATUS_CHOICES, default="new")
    
    property_type = models.CharField(max_length=20,choices=PROPERTY_TYPE_CHOICES,blank=True, default="")

    preferred_location = models.CharField(
        max_length=100,
        blank=True, default=""
    )
    purchase_timeline = models.CharField(
        max_length=20,
        choices=PURCHASE_TIMELINE_CHOICES,
        blank=True, default=""
    )
    budget_max = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,default=None
    )
   
    # ======================
    # CALL FEEDBACK
    # ======================
    interest_level = models.CharField(
        max_length=10,
        choices=INTEREST_LEVEL_CHOICES,
        blank=True,default=""
    )

    next_action = models.CharField(
        max_length=255,
        blank=True, default=""
    )

    client_response = models.TextField(blank=True,   default="")
    objections = models.TextField(blank=True,  default="")
    
    
    # AGENT MANUAL RESPONSE (FREE TEXT)
    
    agent_note = models.TextField(
        blank=True,
         default="",
        help_text="Agent call response / remarks"
    )

    # FOLLOW-UP REMINDER
    follow_up_at = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text="Next follow-up date & time"
    )

    # TIMESTAMPS
    created_at = models.DateTimeField(auto_now_add=True)

    assigned_at = models.DateTimeField(auto_now=True,
    null=True,
    blank=True)

    updated_at = models.DateTimeField(
    auto_now=True)
    def __str__(self):
        return self.title


class TaskHistory(models.Model):

    task = models.ForeignKey(
        Task,
        on_delete=models.CASCADE,
        related_name="history"
    )

    updated_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )

    # snapshot of important fields
    status = models.CharField(
        max_length=20,choices=Task.STATUS_CHOICES,
        default="new"   #  IMPORTANT
    )

    interest_level = models.CharField(
        max_length=10,
        choices=Task.INTEREST_LEVEL_CHOICES,
        blank=True
    )

    client_response = models.TextField(blank=True)
    objections = models.TextField(blank=True)
    next_action = models.CharField(max_length=255, blank=True)

    note = models.TextField(
        help_text="Associate call notes",
        blank=True,
        default=""
    )

    follow_up_at = models.DateTimeField(
        null=True,
        blank=True
    )

    updated_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.task.title} - {self.updated_at}"



class Properties(models.Model):
    name = models.CharField(max_length=200)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    image = models.ImageField(upload_to='products/', blank=True, null=True)

    def __str__(self):
        return self.name