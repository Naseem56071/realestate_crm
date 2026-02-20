import re
from decimal import Decimal
from django.db.models import Count, Q
from django.utils import timezone
from django.http import JsonResponse
from datetime import timedelta, datetime, time
from django.utils.dateparse import parse_datetime
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.http.response import HttpResponse
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from accounts.models import User, Task, TaskHistory, Properties, OTP, Payment
from accounts.decorators import role_required
from accounts.utils import send_sms, generate_otp, lead_email_send
from django.core.paginator import Paginator
from django.contrib.auth.decorators import permission_required
from django.conf import settings
import razorpay
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator


def contact_us(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        message = request.POST.get("message")
        if not re.fullmatch(r"\d{10}", phone):
            messages.error(
                request, "Phone number must contain exactly 10 digits.")
            return redirect("contact")
        # Example: save to DB or send email
        agent = (User.objects.filter(role="agent").annotate(
            task_count=Count("agent_tasks")).order_by("task_count", "id").first())

        task = Task.objects.create(
            name=name,
            email=email,
            phone=phone,
            description=message,
            agent=agent,

        )
        lead_email_send(task)

        messages.success(request, "Your message has been sent successfully!")
        return redirect("contact")
    return render(request, 'accounts/contact.html')


# LOGIN VIEW
def login_view(request):
    if request.user.is_authenticated:
        # Redirect already logged-in users based on role
        if request.user.role == "admin":
            return redirect("dashboard")
        elif request.user.role == "agent":
            return redirect("agent.dashboard")  # agent route
        else:
            return redirect("associate.dashboard")  # associate route

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()
        try:
            user_obj = User.objects.get(email=email)
            print(
                f"User found: {user_obj.email}, Role: {user_obj.role}, Active: {user_obj.is_active}")
        except User.DoesNotExist:
            print("No user with this email")
            messages.error(request, "Invalid email or password")
            return redirect("login")

        user = authenticate(request, email=email, password=password)
        if user is not None and user.is_active:
            auth_login(request, user)
            messages.success(
                request, f"{request.user.name}, Logged in successfully!")

            # Redirect based on role
            if user.role == "admin":
                return redirect("dashboard")  # admin route

            elif user.role == "agent":
                return redirect("agent.dashboard")  # agent route

            elif user.role == "associate":
                return redirect("associate.dashboard")  # associate route
        else:
            messages.error(request, "Invalid email or password")
            return redirect("login")

    return render(request, "accounts/login.html")


# forgot password
def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")

        user = User.objects.filter(email=email).first()

        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            reset_link = request.build_absolute_uri(
                reverse('reset_password', kwargs={
                        'uidb64': uid, 'token': token})
            )

            send_mail(
                "Reset Your Password",
                f"Click the link to reset password:\n{reset_link}",
                settings.EMAIL_HOST_USER,
                [email]
            )
        # SAME message always
        messages.success(
            request, "If this email exists, a reset link was sent to you gmail.")
        return redirect('forgot_password')

    return render(request, "accounts/forgot.html")


# rest password


def reset_password(request, uidb64, token):

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except Exception as e:
        user = None
        print(e)

    if user and default_token_generator.check_token(user, token):
        if request.method == "POST":
            password = request.POST.get("password").strip()
            confirm_password = request.POST.get("confirm_password")

            if password != confirm_password:
                messages.error(request, "Passwords do not match")
                return redirect('reset_password')

               # Strong password validation
            if len(password) < 8:
                messages.error(
                    request, "Password must be at least 8 characters")
                return redirect("reset_password")

            if not re.search(r"[A-Z]", password):
                messages.error(
                    request, "Password must contain at least one uppercase letter")
                return redirect("reset_password")

            if not re.search(r"[a-z]", password):
                messages.error(
                    request, "Password must contain at least one lowercase letter")
                return redirect("reset_password")

            if not re.search(r"[0-9]", password):
                messages.error(
                    request, "Password must contain at least one number")
                return redirect("reset_password")

            if not re.search(r"[!@#$%^&*()_+=\[{\]};:<>|./?,-]", password):
                messages.error(
                    request, "Password must contain at least one special character")
                return redirect("reset_password")
            user.set_password(password)
            user.save()
            messages.success(request, "Password updated. Login now.")
            return redirect("login")

        return render(request, "accounts/reset_password.html")

    # invalid token
    return render(request, "accounts/invalid_link.html")

# sends otp


def phone_login_view(request):
    if request.method == "POST":
        phone = request.POST.get("phone")

        if not phone or not phone.isdigit() or len(phone) != 10:
            messages.error(request, "Enter a valid 10-digit phone number")
            return redirect("phone.login")

        user = User.objects.filter(phone=phone, is_active=True).first()
        if not user:
            messages.error(request, "User not found")
            return redirect("phone.login")

        # 1️ Generate OTP
        otp_code = generate_otp()

        # 2 Send SMS FIRST
        sms_success, sms_response = send_sms(phone, otp_code)

        print(sms_response)

        if not sms_success:
            messages.error(request, "Failed to send OTP. Please try again.")
            print("SMS ERROR:", sms_response)
            return redirect("phone.login")

        # 3️ Delete old OTPs from db
        OTP.objects.filter(phone=phone).delete()

        # 4️ Save OTP ONLY after SMS success
        OTP.objects.create(phone=phone, otp=str(otp_code))

        # 5️ Save phone in session
        request.session["otp_phone"] = phone

        messages.success(request, "OTP sent successfully")
        return redirect("phone.otp-verify")

    return render(request, 'accounts/phone_num_login_otp.html')

# checks otp and login to the page


def verify_otp_view(request):
    # getting phone number from server
    phone = request.session.get("otp_phone")

    if not phone:
        messages.error(request, "Session expired")
        return redirect("phone.login")

    if request.method == "POST":
        entered_otp = request.POST.get("otp")

        #  1. Fetch OTP from DB
        otp_obj = OTP.objects.filter(phone=phone).first()
        if not otp_obj:
            messages.error(request, "OTP expired")
            return redirect("phone.login")

        #  2. Check expiry
        if otp_obj.is_expired():
            otp_obj.delete()
            messages.error(request, "OTP expired")
            return redirect("phone.login")

        #  3. MATCH OTP
        if otp_obj.otp != entered_otp:
            messages.error(request, "Invalid OTP")
            return redirect("phone.otp-verify")

        #  4. OTP MATCHED → LOGIN USER
        else:
            user = User.objects.get(phone=phone)
            auth_login(request, user)
            #  5. CLEANUP
            otp_obj.delete()
            del request.session["otp_phone"]
            messages.success(request, f"{user.name}, Logged in successfully!")
            #  Role-based redirect
            if user.role == "admin":
                return redirect("dashboard")
            elif user.role == "agent":
                return redirect("agent.dashboard")
            else:
                return redirect("associate.dashboard")

    return render(request, "accounts/verify_otp.html")


@login_required
@role_required(["admin"])
def assign_permissions(request):

    users = User.objects.filter(role__in=["agent", "associate"])
    selected_user = None
    user_permissions = []

    task_permissions = [
        ("can_view_lead", "View Lead"),
        ("can_assign_lead", "Assign Lead"),
        ("can_update_lead", "Update Lead"),
        ("can_delete_lead", "Delete Lead"),
    ]

    product_permissions = [
        ("view_product", "View Products"),
        ("add_product", "Add Products"),
        ("change_product", "Update Products"),
        ("delete_product", "Delete Products"),
    ]

    navigation_permissions = [
        ("can_view_dashboard", "Dashboard"),
        ("can_view_admin", "Admin"),
        ("can_view_products", "Products"),
        ("can_view_leads", "Leads"),
        ("can_view_permissions", "Permissions"),
        ("can_view_contacts", "Contacts"),
    ]

    # GET
    user_id = request.GET.get("user_id")
    if user_id:
        selected_user = get_object_or_404(User, id=user_id)
        user_permissions = selected_user.user_permissions.values_list(
            "codename", flat=True
        )

    # POST
    if request.method == "POST":
        user_id = request.POST.get("user_id")
        permission_codes = request.POST.getlist("permissions")
        selected_user = get_object_or_404(User, id=user_id)

        selected_user.user_permissions.clear()

        for code in permission_codes:
            perm = Permission.objects.filter(codename=code).first()
            if perm:
                selected_user.user_permissions.add(perm)

        messages.success(request, "Permissions updated successfully")
        return redirect(f"{request.path}?user_id={selected_user.id}")

    return render(
        request,
        "accounts/admin/assign_permissions.html",
        {
            "users": users,
            "selected_user": selected_user,
            "user_permissions": user_permissions,
            "task_permissions": task_permissions,
            "product_permissions": product_permissions,
            "navigation_permissions": navigation_permissions,
        }
    )


@login_required
def logout_view(request):
    username = request.user.name
    auth_logout(request)
    messages.success(
        request, f"{username}, You have been logged out successfully.")
    return redirect("login")


@login_required
@role_required(['admin'])
def contact_details(request):
    tasks = Task.objects.all()
    query = request.GET.get('name', "").strip()
    if query:
        query = query.lower()
        tasks = tasks.filter(Q(name__icontains=query) |
                             Q(email__icontains=query))
    paginator = Paginator(tasks, 2)  # show 5 records per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(request, "accounts/admin/contact_details.html", {"page_obj": page_obj})


@login_required
@role_required(["admin"])
def edit_contact_details(request, id):
    edit_contact = get_object_or_404(Task, id=id)
    if request.method == 'POST':
        edit_name = request.POST.get('name')
        edit_phone = request.POST.get('phone')
        edit_email = request.POST.get('email')

        if not re.fullmatch(r"\d{10}", edit_phone):
            messages.error(
                request, "Phone number must contain exactly 10 digits.")
            return redirect("contact-details")

        edit_contact.name = edit_name
        edit_contact.phone = edit_phone
        edit_contact.email = edit_email
        edit_contact.save()
        messages.success(request, 'contact details updated successfully')
        return redirect('contact-details')

    return render(request, 'accounts/admin/edit_contact_details.html', {'edit_contact': edit_contact})


@login_required
@role_required(['admin'])
def delete_contact_details(request, id):
    delete_contact_details = get_object_or_404(Task, id=id)
    if request.method == "POST":
        delete_contact_details .delete()
        messages.success(request, "deleted successfully")
        return redirect("contact-details")

    return redirect('contact-details')


@login_required
def dashboard(request):
    if request.user.role != "admin":
        messages.error(
            request, "You do not have permission to view this page.")
        return redirect("login")
    return render(
        request,
        "accounts/dashboard.html",

    )


@login_required
def upload_profile_image(request):
    if request.method == "POST":
        image = request.FILES.get("profile_image")

        if image:
            request.user.profile_image = image
            request.user.save()
            messages.success(request, "Profile image updated successfully")
            return redirect(request.path)
        else:
            messages.error(request, "Please select a file")

    return render(request, 'accounts/admin/upload_profile_image.html')


@login_required
def delete_profile_image(request):
    if request.user.profile_image:
        request.user.profile_image.delete(save=False)
        request.user.profile_image = None
        request.user.save()
        messages.success(request, "Profile image deleted successfully.")

    return redirect(request.META.get("HTTP_REFERER", "/"))


@login_required
@role_required(['admin'])
def admin_dashboard_view(request):
    users = User.objects.filter(role__in=["agent", "associate"])
    name = request.GET.get('name', '').strip()
    role = request.GET.get('role', '').strip()
    if name:
        users = users.filter(Q(name__icontains=name) |
                             Q(email__icontains=name))
    if role:
        users = users.filter(role=role)

    tasks = Task.objects.all().select_related('agent', 'associate')
    histories = TaskHistory.objects.filter(
        task__in=tasks).order_by('task', 'updated_at')
    total_users = User.objects.count()
    total_agents = User.objects.filter(role="agent").count()
    total_associates = User.objects.filter(role='associate').count()

    paginator = Paginator(users, 2)  # show 5 records per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(request, 'accounts/admin/admin_dashboard.html', {
        'page_obj': page_obj,
        "tasks": tasks,
        "histories": histories,
        "total_users": total_users,
        "total_agents": total_agents,
        "total_associates": total_associates,
    })


@login_required
def update_associate_and_agent(request, user_id):
    edit_user_details = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        name = request.POST.get('name')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        image = request.FILES.get('image')

        edit_user_details.name = name
        edit_user_details.phone = phone
        edit_user_details.email = email
        if image:
            edit_user_details.profile_image = image
        edit_user_details.save()
        messages.success(
            request, "Agent and Associate details Updated Successfully")
        return redirect("admin.dashboard")

    return render(request, 'accounts/admin/edit_associate_agent.html', {'edit_user_details': edit_user_details})


@role_required(['admin'])
def toggle_user_status(request, id):
    user = get_object_or_404(User, id=id)

    # Toggle status
    user.is_active = not user.is_active
    user.save()

    if user.is_active:
        messages.success(request, "User Activated Successfully")
    else:
        messages.success(request, "User Deactivated Successfully")

    return redirect('admin.dashboard')


@role_required(["admin"])
def admin_deletes_agents_associates(request, id):
    delete_users = User.objects.get(id=id)
    delete_users.delete()
    messages.success(request, f'{delete_users.name},deleted successfully')
    return redirect("admin.dashboard")


@login_required
@role_required(["admin"])
def list_lead_details(request):

    leads = Task.objects.all()

    today = timezone.localdate()
    yesterday = today - timedelta(days=1)
    start_of_week = today - timedelta(days=7)

    date_filter = request.GET.get("date")
    agent_id = request.GET.get("agent")
    associate_id = request.GET.get("associate")

    if date_filter == "today":
        start = timezone.make_aware(datetime.combine(today, time.min))
        end = timezone.make_aware(datetime.combine(today, time.max))
        leads = leads.filter(created_at__range=(start, end))

    elif date_filter == "yesterday":
        start = timezone.make_aware(datetime.combine(yesterday, time.min))
        end = timezone.make_aware(datetime.combine(yesterday, time.max))
        leads = leads.filter(created_at__range=(start, end))

    elif date_filter == "this-week":
        start = timezone.make_aware(datetime.combine(start_of_week, time.min))
        end = timezone.make_aware(datetime.combine(today, time.max))
        leads = leads.filter(created_at__range=(start, end))

    if agent_id:
        leads = leads.filter(agent_id=agent_id)
    if associate_id:
        leads = leads.filter(associate_id=associate_id)

    paginator = Paginator(leads.order_by("-created_at"),
                          1)  # show 5 records per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    total_leads = leads.count()
    pending_leads = leads.filter(status="pending").count()
    new_leads = leads.filter(status="new").count()
    in_progress_lead = leads.filter(status="in_progress").count()
    completed_leads = leads.filter(status="completed").count()

    agents = User.objects.filter(role='agent')
    associates = User.objects.filter(role='associate')

    return render(
        request,
        "accounts/admin/lead_details.html",
        {
            "page_obj": page_obj,
            "date_filter": date_filter,
            "agents": agents,
            "associates": associates,
            "total_leads": total_leads,
            "pending_leads": pending_leads,
            "new_leads": new_leads,
            "completed_leads": completed_leads,
            "in_progress_lead": in_progress_lead,
        }
    )


@login_required
@role_required(['admin'])
def create_lead(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        message = request.POST.get("message")
        if not re.fullmatch(r"\d{10}", phone):
            messages.error(
                request, "Phone number must contain exactly 10 digits.")
            return redirect("admin.create-lead.dashbiard")
        # Example: save to DB or send email
        agent = (User.objects.filter(role="agent").annotate(
            task_count=Count("agent_tasks")).order_by("task_count", "id").first())

        task = Task.objects.create(
            name=name,
            email=email,
            phone=phone,
            description=message,
            agent=agent,

        )
        lead_email_send(task)

        messages.success(request, "Your message has been sent successfully!")
        return redirect("admin.lead_details.dashboard")
    return render(request, 'accounts/admin/create_lead.html')


@role_required(["admin", "agent"])
def admin_delete_lead(request, id):
    delete_task = get_object_or_404(Task, id=id)
    delete_task.delete()
    messages.success(request, f"{delete_task.name}, lead deleted successfully")
    return redirect('admin.lead_details.dashboard')


@login_required
def admin_dashboard(request):
    if request.user.role != "admin":
        return redirect("login")
    return render(request, "dashboard/admin_dashboard.html")


@login_required
@role_required(["admin"])
def admin_create_agent(request):
    #  Only admin can create agent
    if request.user.role != "admin":
        messages.error(request, "Unauthorized access")
        return redirect("dashboard")

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        email = request.POST.get("email", "").strip()
        role = request.POST.get("role")
        phone = request.POST.get('phone').strip()
        password = request.POST.get("password").strip()
        confirm_password = request.POST.get("confirm-password").strip()

        # Name validation
        if not name:
            messages.error(request, "Name is required")
            return redirect("dashboard")

        if len(name) < 3:
            messages.error(request, "Name must be at least 3 characters")
            return redirect("dashboard")

        if not name.replace(" ", "").isalpha():
            messages.error(request, "Name must contain only letters")
            return redirect("dashboard")
        # phone number validation
        if len(phone) != 10:
            messages.error(request, "Phone Number must contaion 10 digits")
            return redirect('dashboard')

        # Password match
        if password != confirm_password:
            messages.error(request, "Passwords did not match")
            return redirect("dashboard")

        # Strong password validation
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters")
            return redirect("dashboard")

        if not re.search(r"[A-Z]", password):
            messages.error(
                request, "Password must contain at least one uppercase letter"
            )
            return redirect("dashboard")

        if not re.search(r"[a-z]", password):
            messages.error(
                request, "Password must contain at least one lowercase letter"
            )
            return redirect("dashboard")

        if not re.search(r"[0-9]", password):
            messages.error(
                request, "Password must contain at least one number")
            return redirect("dashboard")

        if not re.search(r"[!@#$%^&*()_+=\[{\]};:<>|./?,-]", password):
            messages.error(
                request, "Password must contain at least one special character"
            )
            return redirect("dashboard")

        # Email uniqueness check
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
            return redirect("dashboard")

        # Create agent
        User.objects.create_user(
            email=email,
            name=name,
            password=password,
            phone=phone,
            role=role,
        )

        messages.success(request, "Agent created successfully")
        return redirect("admin.dashboard")

    return render(request, "accounts/admin/create_agent_account.html")


@login_required
@role_required(["agent"])
def agent_dashboard(request):
    return render(request, "accounts/agent/dashboard.html")


@login_required
@role_required(["agent"])
def agent_dashboard_view(request):
    users = User.objects.filter(role="associate")
    return render(request, "accounts/agent/agent_dashboard_view.html", {'users': users})


@role_required(["agent"])
def agents_deleted_associates(request, id):
    delete_users = get_object_or_404(User, id=id)
    delete_users.delete()
    messages.success(request, f'{delete_users.name},deleted successfully')
    return redirect("admin.dashboard")


@login_required
@role_required(["agent"])
def agent_create_associate(request):
    #  Only agent can create agent
    if request.user.role != "agent":
        messages.error(request, "Unauthorized access")
        return redirect("agent.dashboard")

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        email = request.POST.get("email", "").strip()
        role = request.POST.get("role", "").strip()
        phone = request.POST.get('phone', "").strip()
        password = request.POST.get("password", "").strip()
        confirm_password = request.POST.get("confirm-password", "").strip()

        # Name validation
        if not name:
            messages.error(request, "Name is required")
            return redirect("agent.dashboard")

        if len(name) < 3:
            messages.error(request, "Name must be at least 3 characters")
            return redirect("agent.dashboard")

        if not name.replace(" ", "").isalpha():
            messages.error(request, "Name must contain only letters")
            return redirect("agent.dashboard")

        if len(phone) != 10:
            messages.error(request, "Phone Number must contaion 10 digits")
            return redirect('agent.dashboard')

        # Password match
        if password != confirm_password:
            messages.error(request, "Passwords did not match")
            return redirect("agent.dashboard")

        # Strong password validation
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters")
            return redirect("agent.dashboard")

        if not re.search(r"[A-Z]", password):
            messages.error(
                request, "Password must contain at least one uppercase letter"
            )
            return redirect("agent.dashboard")

        if not re.search(r"[a-z]", password):
            messages.error(
                request, "Password must contain at least one lowercase letter"
            )
            return redirect("agent.dashboard")

        if not re.search(r"[0-9]", password):
            messages.error(
                request, "Password must contain at least one number")
            return redirect("agent.dashboard")

        if not re.search(r"[!@#$%^&*()_+=\[{\]};:<>|./?,-]", password):
            messages.error(
                request, "Password must contain at least one special character"
            )
            return redirect("agent.dashboard")

        # Email uniqueness check
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
            return redirect("agent.dashboard")

        # Create agent
        associate = User.objects.create_user(
            email=email,
            name=name,
            password=password,
            phone=phone,
            role=role,
        )
        associate.created_by = request.user   # agent
        associate.save()
        messages.success(request, "associate created successfully")
        return redirect("agent.dashboard")

    return render(request, 'accounts/agent/create_associate_account.html')


def update_associate(request, id):
    edit_associate = get_object_or_404(User, id=id)
    if request.method == 'POST':
        name = request.POST.get('name')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        image = request.POST.get('image')

        edit_associate.name = name
        edit_associate.phone = phone
        edit_associate.email = email
        if image:
            edit_associate.profile_image = image
        edit_associate.save()
        messages.success(request, 'update associate details successfully')
        return redirect('agent.view.dashboard')

    return render(request, "accounts/agent/edit_associate_acc.html", {"edit_associate": edit_associate})


@login_required
@role_required(["associate"])
def associate_dashboard(request):
    return render(request, "accounts/associate.html")


@login_required
@role_required(["associate"])
def associate_tracking_updates(request):
    tasks = Task.objects.all().select_related('agent', 'associate')
    if request.user.role == "associate":
        # Associate → only own history
        histories = TaskHistory.objects.filter(
            task__in=tasks,
            updated_by=request.user
        )
    else:
        # Admin / Agent → see all histories
        histories = TaskHistory.objects.filter(
            task__in=tasks
        )
    return render(request, "accounts/associate/associate_index.html", {'histories': histories})


@login_required
@role_required(['admin', 'agent', 'associate'])
def client_tracking_history(request, associate_id, task_id):
    history = (
        TaskHistory.objects.filter(task_id=task_id, updated_by_id=associate_id).select_related(
            "updated_by", "task").order_by("-updated_at")
    )
    task_details = task_details = get_object_or_404(Task, id=task_id)
    last_updated_by = history.first().updated_by if history.exists() else None
    return render(request, 'accounts/admin/client_tracking_history_updated_by_associate.html', {"history": history, 'last_updated_by': last_updated_by, "task_details": task_details})


@login_required
@role_required(["agent"])
def agent_view_task(request):
    leads = Task.objects.filter(agent=request.user)
    paginator = Paginator(leads, 1)  # show 5 records per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, "accounts/agent/view_lead.html", {"page_obj": page_obj})


@login_required
@role_required(["agent"])
@permission_required('accounts.can_assign_lead', raise_exception=True)
def agent_assign_task(request, name):
    associates = User.objects.filter(
        role="associate",
        created_by=request.user
    )

    task = get_object_or_404(Task, name=name, agent=request.user)
    assigned_date_time = timezone.now()
    if request.method == "POST":

        associate_id = request.POST.get("associate")
        if not associate_id:
            messages.error(request, "Please select an associate.")
            return redirect(request.path)

        associate = get_object_or_404(
            User, id=associate_id, role="associate", created_by=request.user)

        #  UPDATE existing task
        task.associate = associate
        task.assigned_at = assigned_date_time
        task.save()

        messages.success(request, "Task updated successfully.")
        return redirect("agent.view_task.dashboard")

    return render(
        request,
        "accounts/agent/assign_lead.html",
        {"associates": associates, "task": task},
    )


@login_required
@role_required(["agent"])
def agent_update_task(request, id):
    if not request.user.has_perm("accounts.can_update_lead"):
        return HttpResponse("You can't update task", status=403)

    task = get_object_or_404(Task, id=id, agent=request.user)

    associates = User.objects.filter(role="associate")

    if request.method == "POST":
        task.title = request.POST.get("title")
        task.description = request.POST.get("description")

        associate_id = request.POST.get("associate")

        associate_id = request.POST.get("associate")
        task.associate = get_object_or_404(
            User, id=associate_id, role="associate")
        task.updated_at = timezone.now()

        task.save()
        messages.success(request, "Task updated successfully")
        return redirect("agent.view_task.dashboard")

    return render(
        request,
        "accounts/agent/update_lead.html",
        {"tasks": task, "associates": associates},
    )


@role_required(["agent"])
def delete_task(request, id):
    task = get_object_or_404(Task, id=id, agent=request.user)
    task.delete()
    messages.success(request, "Task deleted")
    return redirect("agent.view_task.dashboard")


@login_required
@role_required(["associate"])
def associate_view_task(request):
    tasks = Task.objects.filter(associate=request.user)

    paginator = Paginator(tasks, 2)  # show 5 records per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, "accounts/associate/view_task.html", {"page_obj": page_obj})


@login_required
@role_required(['associate'])
def associate_update_task(request, id):
    task_hisrories = TaskHistory.objects.last()
    task = get_object_or_404(Task, id=id, associate=request.user)
    if request.method == "POST":

        status = request.POST.get("status")
        note = request.POST.get("description")   # input from associate
        updated_at = timezone.now()

        # Update the task's current state
        task.updated_at = updated_at
        task.status = status
        task.save()

        # Log the update in TaskHistory
        TaskHistory.objects.create(
            task=task,
            updated_by=request.user,
            client_response=note,
            status=status
        )
        messages.success(request, "updated successfully")
        return redirect('associate.dashboard')

    return render(request, 'accounts/associate/update_task.html', {'task': task, 'task_hisrories': task_hisrories})


# Product adding ,deleting , listing and updating

@login_required
@role_required(['admin'])
def add_products(request):
    if request.method == "POST":
        created_at = timezone.now()
        product_name = request.POST.get('p_name')
        product_price = request.POST.get('price')
        product_description = request.POST.get('description')
        product_img = request.FILES.get("p_image")
        p_location = request.POST.get('location')

        Properties.objects.create(
            name=product_name,
            price=product_price,
            description=product_description,
            created_at=created_at,
            image=product_img,
            location=p_location
        )
        messages.success(request, "Product added Successfully")
        return redirect('admin.list_products.dashboard')
    return render(request, 'accounts/products/add_products.html')


@login_required
@role_required(['admin', 'agent'])
@permission_required("accounts.view_product", raise_exception=True)
def list_products(request):
    if not request.user.has_perm("accounts.view_product"):
        return HttpResponse("You dont have permissoin to view this page")
    products = Properties.objects.all()
    query = request.GET.get('location')
    if query:
        query = query.lower()
        products = products.filter(location=query)

    paginator = Paginator(products, 2)  # show 5 records per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(request, "accounts/products/view_products.html", {'page_obj': page_obj})


@login_required
@role_required(['admin'])
def update_product(request, id):
    product = get_object_or_404(Properties, id=id)
    if request.method == 'POST':
        P_name = request.POST.get('p_name')
        price = request.POST.get('price')
        description = request.POST.get('description')
        p_image = request.FILES.get('p_image')
        p_location = request.POST.get('location')

        updated_at = timezone.now()

        product.name = P_name
        product.price = price
        product.description = description
        product.updated_at = updated_at
        product.location = p_location

        if p_image:
            product.image = p_image

        product.save()
        messages.success(request, "Product Updated Successfully")
        return redirect('dashboard')

    return render(request, 'accounts/products/update_products.html', {'product': product})


@role_required(['admin'])
def delete_product(request, id):
    product = get_object_or_404(Properties, id=id)
    if request.method == "POST":
        product.delete()
        messages.success(request, "Product deleted successfully")
        return redirect("dashboard")

    return redirect('dashboard')


# payment gateway
client = razorpay.Client(
    auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))


def check_out_product(request, product_id):
    product = get_object_or_404(Properties, id=product_id)
    return render(request, 'accounts/products/check_out_product.html', {"product": product})


@csrf_exempt
def create_payment(request, product_id):
    product = get_object_or_404(Properties, id=product_id)

    order_data = {
        'amount': int(product.booking_amount * 100),
        'currency': "INR",
        'payment_capture': "1"
    }
    razorpay_order = client.order.create(order_data)

    Payment.objects.create(
        user=request.user,
        product=product,
        amount=product.booking_amount,
        razorpay_order_id=razorpay_order['id']
    )
    return JsonResponse({
        'order_id': razorpay_order['id'],
        'razorpay_key_id': settings.RAZORPAY_KEY_ID,
        'product_name': product.name,
        'amount': order_data["amount"],
        'razorpay_callback_url': settings.RAZORPAY_CALLBACK_URL
    })


@csrf_exempt
def payment_verify(request):
    if 'razorpay_signature' in request.POST:
        order_id = request.POST.get('razorpay_order_id')
        payment_id = request.POST.get('razorpay_payment_id')
        signature = request.POST.get('razorpay_signature')

        payment = get_object_or_404(Payment, razorpay_order_id=order_id)

        if client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }):
            payment.razorpay_order_id = order_id
            payment.razorpay_payment_id = payment_id
            payment.razorpay_signature = signature
            payment.status = "success"
            payment.is_paid = True
            payment.save()
            return HttpResponse("payment success")
        else:
            payment.status = "failed"
            payment.is_paid = False
            payment.save()
            return JsonResponse({'status': 'failed'})
    else:
        return HttpResponse("payment failed")
