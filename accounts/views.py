import re
from django.db.models import Count
from datetime import datetime
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.http.response import HttpResponse
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from accounts.models import User, Task, TaskHistory, Properties, OTP
from accounts.decorators import role_required
from accounts.utils import send_sms, generate_otp


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
        email = request.POST.get("email")
        password = request.POST.get("password")
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

#sends otp 
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

        if not sms_success:
            messages.error(request, "Failed to send OTP. Please try again.")
            print("SMS ERROR:", sms_response)
            return redirect("phone.login")

        # 3️ Delete old OTPs
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
    if request.user.role != "admin":
        return HttpResponse("You don't have permission", status=403)

    users = User.objects.filter(role__in=["agent", "associate"])
    selected_user = None
    user_permissions = []

    content_type = ContentType.objects.get_for_model(Task)

    # Get user_id from GET when user selects a user
    user_id = request.GET.get("user_id")
    if user_id:
        selected_user = get_object_or_404(User, id=user_id)
        # Load assigned permissions for this user
        user_permissions = selected_user.user_permissions.filter(
            content_type=content_type
        ).values_list("codename", flat=True)

    if request.method == "POST":
        user_id = request.POST.get("user_id")
        permission_codes = request.POST.getlist("permissions")
        selected_user = get_object_or_404(User, id=user_id)

        # Remove old task permissions
        old_perms = selected_user.user_permissions.filter(
            content_type=content_type
        )

        for perm in old_perms:
            selected_user.user_permissions.remove(perm)

        # Add new permissions
        for code in permission_codes:
            permission = Permission.objects.get(
                codename=code,
                content_type=content_type
            )
            selected_user.user_permissions.add(permission)

        # Reload user_permissions for rendering
        user_permissions = selected_user.user_permissions.filter(
            content_type=content_type
        ).values_list("codename", flat=True)
        messages.success(request, "added permissions")
        return redirect("assign_permissions")

    return render(request, "accounts/admin/assign_permissions.html", {
        "users": users,
        "selected_user": selected_user,
        "user_permissions": user_permissions,
    })


@login_required
def logout_view(request):
    username = request.user.name
    auth_logout(request)
    messages.success(
        request, f"{username}, You have been logged out successfully.")
    return redirect("login")


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
        agent = (User.objects.filter(role="agent").annotate(task_count=Count("agent_tasks")).order_by("task_count", "id").first()
                 )
        Task.objects.create(
            name=name,
            email=email,
            phone=phone,
            description=message,
            agent=agent,

        )

        messages.success(request, "Your message has been sent successfully!")
        return redirect("contact")
    return render(request, 'accounts/contact.html')


@login_required
@role_required(['admin'])
def contact_details(request):
    tasks = Task.objects.all()
    return render(request, "accounts/admin/contact_details.html", {'tasks': tasks})


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
@role_required(['admin'])
def admin_dashboard_view(request):
    tasks = Task.objects.all().select_related('agent', 'associate')
    histories = TaskHistory.objects.filter(
        task__in=tasks).order_by('task', 'updated_at')
    users = User.objects.all()
    total_users = User.objects.count()
    total_agents = User.objects.filter(role="agent").count()
    total_associates = User.objects.filter(role='associate').count()
    return render(request, 'accounts/admin/admin_dashboard.html', {
        'users': users,
        "tasks": tasks,
        "histories": histories,
        "total_users": total_users,
        "total_agents": total_agents,
        "total_associates": total_associates,
    })


@role_required(["admin"])
def admin_deletes_agents_associates(request, id):
    delete_users = User.objects.get(id=id)
    delete_users.delete()
    messages.success(request, f'{delete_users.name},deleted successfully')
    return redirect("admin.dashboard")


@login_required
@role_required(["admin"])
def lead_details(request):
    leads = Task.objects.all()
    total_leads = Task.objects.count()
    pending_leads = Task.objects.filter(status='pending').count()
    new_leads = Task.objects.filter(status='new').count()
    in_progress_lead = Task.objects.filter(status='in_progress').count()
    completed_leads = Task.objects.filter(status="completed").count()
    return render(request, 'accounts/admin/lead_details.html', {"leads": leads, "total_leads": total_leads, "pending_leads": pending_leads, "new_leads": new_leads, "completed_leads": completed_leads, "in_progress_lead": in_progress_lead})


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
def create_agent(request):
    #  Only admin can create agent
    if request.user.role != "admin":
        messages.error(request, "Unauthorized access")
        return redirect("dashboard")

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        email = request.POST.get("email", "").strip()
        role = request.POST.get("role")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm-password")

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
        user = User.objects.create_user(
            email=email,
            name=name,
            password=password,
            role=role,
        )

        messages.success(request, "Agent created successfully")
        return redirect("dashboard")

    return redirect("dashboard")


@login_required
@role_required(["agent"])
def agent_dashboard(request):
    return render(request, "accounts/agent/dashboard.html")


@login_required
@role_required(["agent"])
def agent_dashboard_view(request):
    users = User.objects.all()
    return render(request, "accounts/agent/agent_dashboard_view.html", {'users': users})

# pending


@role_required(["agent"])
def agents_deleted_associates(request, id):
    delete_users = get_object_or_404(User, id=id)
    delete_users.delete()
    messages.success(request, f'{delete_users.name},deleted successfully')
    return redirect("admin.dashboard")


@login_required
@role_required(["agent"])
def create_associate(request):
    #  Only agent can create agent
    if request.user.role != "agent":
        messages.error(request, "Unauthorized access")
        return redirect("agent.dashboard")

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        email = request.POST.get("email", "").strip()
        role = request.POST.get("role", "").strip()
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
            role=role,
        )
        associate.created_by = request.user   # agent
        associate.save()
        messages.success(request, "associate created successfully")
        return redirect("agent.dashboard")

    return redirect("agent.dashboard")


@login_required
@role_required(["associate"])
def associate_dashboard(request):
    return render(request, "accounts/associate.html")


@login_required
@role_required(["associate", "admin", "agent"])
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
@role_required(["agent"])
def agent_view_task(request):
    leads = Task.objects.filter(agent=request.user)

    return render(request, "accounts/agent/view_lead.html", {"leads": leads})


@login_required
@role_required(["agent"])
def agent_assign_task(request, name):
    associates = User.objects.filter(
        role="associate",
        created_by=request.user
    )

    task = get_object_or_404(Task, name=name, agent=request.user)

    if request.method == "POST":
        associate_id = request.POST.get("associate")
        assigned_date_time = request.POST.get("assigned_date_time")

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
    if not request.user.has_perm("accounts.can_update_task"):
        return HttpResponse("You can't update task", status=403)

    task = get_object_or_404(Task, id=id, agent=request.user)

    associates = User.objects.filter(role="associate")

    if request.method == "POST":
        task.title = request.POST.get("title")
        task.description = request.POST.get("description")

        start_time = request.POST.get("start_time")
        if start_time:
            task.created_at = parse_datetime(start_time)

        associate_id = request.POST.get("associate")

        associate_id = request.POST.get("associate")
        task.associate = get_object_or_404(
            User, id=associate_id, role="associate")

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
    return render(request, "accounts/associate/view_task.html", {"tasks": tasks})


@login_required
@role_required(['associate'])
def associate_update_task(request, id):
    task_hisrories = TaskHistory.objects.last()
    task = get_object_or_404(Task, id=id, associate=request.user)
    if request.method == "POST":
        description = request.POST.get("description")  # input from associate
        status = request.POST.get("status")
        note = request.POST.get("description")

        # Update the task's current state
        task.status = status
        task.save()

        # Log the update in TaskHistory
        task_his = TaskHistory.objects.create(
            task=task,
            updated_by=request.user,
            client_response=note,
            status=status
        )
        messages.success(request, "updated successfully")
        return redirect('associate.dashboard')

    return render(request, 'accounts/associate/update_task.html', {'task': task, 'task_hisrories': task_hisrories})


@login_required
@role_required(['admin'])
def add_products(request):
    if request.method == "POST":
        product_name = request.POST.get('p_name')
        product_price = request.POST.get('price')
        product_description = request.POST.get('description')
        product_img = request.FILES.get("p_image")
        created_at = request.POST.get('create_at')

        Properties.objects.create(
            name=product_name,
            price=product_price,
            description=product_description,
            created_at=created_at,
            image=product_img
        )
        messages.success(request, "Product added Successfully")
        return redirect('dashboard')
    return render(request, 'accounts/products/add_products.html')


@login_required
@role_required(['admin'])
def list_products(request):
    products = Properties.objects.all()
    return render(request, "accounts/products/view_products.html", {'products': products})


@login_required
@role_required(['admin'])
def update_product(request, id):
    product = get_object_or_404(Properties, id=id)
    if request.method == 'POST':
        P_name = request.POST.get('p_name')
        price = request.POST.get('price')
        description = request.POST.get('description')
        p_image = request.FILES.get('p_image')
        updated_at = request.POST.get('updated_at')

        product.name = P_name
        product.price = price
        product.description = description
        product.created_at = updated_at

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
