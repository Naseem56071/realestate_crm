from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from accounts.manager import UserManager
from django.utils import timezone


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ("admin", "Admin"),
        ("agent", "Agent"),
        ("associate", "Associate"),
    )

    email = models.EmailField(unique=True)
    name = models.CharField(max_length=70, default=None)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    phone = models.CharField(
        max_length=10,
        unique=True,
        null=True,
        blank=True,
        help_text="Enter 10 digit mobile number"
    )

    created_by = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_associates"
    )


    profile_image = models.ImageField(
    upload_to="profile_images/",
    blank=True,
    null=True,
    default=None   # IMPORTANT
    )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        permissions = [
            ("can_view_dashboard", "Can view dashboard"),
            ("can_view_admin", "Can view admin section"),
            ("can_view_products", "Can view products"),
            ("can_view_leads", "Can view leads"),
            ("can_view_permissions", "Can view permissions"),
            ("can_view_contacts", "Can view contacts"),
        ]

    def __str__(self):
        return self.email


class OTP(models.Model):
    phone = models.CharField(max_length=10)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=5)


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
    phone = models.CharField(max_length=20, default="")
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
        null=True,  # allow NULL in database
        blank=True  # allow empty in forms
    )

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="new")

    property_type = models.CharField(
        max_length=20, choices=PROPERTY_TYPE_CHOICES, blank=True, default="")

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
        blank=True, default=None
    )

    # ======================
    # CALL FEEDBACK
    # ======================
    interest_level = models.CharField(
        max_length=10,
        choices=INTEREST_LEVEL_CHOICES,
        blank=True, default=""
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

    class Meta:
        permissions = [
            ("can_assign_task", "Can assign task"),
            ("can_update_task", "Can update task"),
            ("can_view_all_tasks", "Can view all tasks"),
            ("can_delete_task", "Can delete tasks"),
        ]


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
        max_length=20, choices=Task.STATUS_CHOICES,
        default="new"  # IMPORTANT
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
    CITY_CHOICES = [
        ('hyderabad', 'Hyderabad'),
        ('bangalore', 'Bangalore'),
        ('chennai', 'Chennai'),
    ]

    location = models.CharField(
        max_length=50, choices=CITY_CHOICES, default=None)
    name = models.CharField(max_length=200)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to='products/', blank=True, null=True)

    def __str__(self):
        return self.name
