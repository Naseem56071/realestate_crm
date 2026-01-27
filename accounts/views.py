import re
from datetime import datetime
from django.utils.dateparse import parse_datetime
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.http.response import HttpResponse, HttpResponseRedirect
from django.contrib.auth.models import AbstractUser
from django.db.models.manager import BaseManager
from accounts.models import User, Task, TaskHistory,Products
from accounts.decorators import role_required


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

        user = authenticate(request, email=email, password=password)
        if user is not None and user.is_active:
            auth_login(request, user)
            messages.success(request, "Logged in successfully!")

            # Redirect based on role
            if user.role == "admin":
                return redirect("dashboard")  # admin route

            elif user.role == "agent":
                return redirect("agent.dashboard")  # agent route

            elif user.role == "associate":
                return redirect("associate.dashboard")  # associate route
        else:
            messages.error(request, "Invalid email or password")

    return render(request, "accounts/login.html")


@login_required
def dashboard(request):
    if request.user.role != "admin":
        messages.error(
            request, "You do not have permission to view this page.")
        return redirect("login")

    tasks = Task.objects.all().select_related('agent', 'associate')
    histories = TaskHistory.objects.filter(
        task__in=tasks).order_by('task', 'updated_at')
    total_users = User.objects.count()
    total_agents = User.objects.filter(role="agent").count()
    total_associates = User.objects.filter(role='associate').count()

    return render(
        request,
        "accounts/dashboard.html",
        {
            "tasks": tasks,
            "histories": histories,
            "total_users": total_users,
            "total_agents": total_agents,
            "total_associates": total_associates,
        }
    )


@login_required
def logout_view(request):
    auth_logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("login")


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
    return render(request, "accounts/agent_dashboard.html")


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
        role = request.POST.get("role")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm-password")

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
        user = User.objects.create_user(
            email=email,
            name=name,
            password=password,
            role=role,
        )

        messages.success(request, "associate created successfully")
        return redirect("agent.dashboard")

    return redirect("agent.dashboard")


@login_required
@role_required(["associate"])
def associate_dashboard(request):
    return render(request, "accounts/associate.html")


@login_required
@role_required(["agent"])
def agent_view_task(request):
    tasks = Task.objects.filter(agent=request.user)
    return render(request, "accounts/agent/view_lead.html", {"tasks": tasks})


@login_required
@role_required(["agent"])
def agent_assign_task(request):
    associates = User.objects.filter(role="associate")
    if request.method == "POST":
        title = request.POST.get("title")
        description = request.POST.get("description")
        start_time = request.POST.get("start_time")
        associate_id = request.POST.get("associate")

        # Validation
        if not title:
            messages.error(request, "Task title is required.")
            return redirect("agent.assign_task.dashboard")

        if not associate_id:
            messages.error(request, "Please select an associate.")
            return redirect("agent.assign_task.dashboard")

        try:
            associate = User.objects.get(id=associate_id, role="associate")
        except User.DoesNotExist:
            messages.error(request, "Invalid associate selected.")
            return redirect("agent.assign_task.dashboard")

        #  Create task
        Task.objects.create(
            title=title,
            description=description,
            agent=request.user,  # logged-in agent
            associate=associate,
            created_at=start_time,
        )

        messages.success(request, "Task assigned successfully.")
        return redirect("agent.assign_lead.dashboard")
    return render(
        request, "accounts/agent/assign_lead.html", {"associates": associates}
    )


@login_required
@role_required(["agent"])
def agent_update_task(request, id):
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

    task = get_object_or_404(Task, id=id, associate=request.user)
    if request.method == "POST":
        description = request.POST.get("description")
        status = request.POST.get("status")
        note = request.POST.get("description")  # input from associate

        # Update the task's current state
        task.description = description
        task.status = status
        task.save()

        # Log the update in TaskHistory
        TaskHistory.objects.create(
            task=task,
            updated_by=request.user,
            description=note,
            status=status
        )
        messages.success(request,"updated successfully")
        return redirect('associate.dashboard')

    return render(request, 'accounts/associate/update_task.html', {'task': task})
@login_required
@role_required(['admin'])
def add_products(request):
    if request.method == "POST":
        product_name=request.POST.get('p_name')
        product_price=request.POST.get('price')
        product_description=request.POST.get('description')
        product_img=request.FILES.get("p_image")
        created_at=request.POST.get('create_at')
        
        Products.objects.create(
            name=product_name,
            price=product_price,
            description=product_description,
            created_at=created_at,
            image=product_img
        )
        messages.success(request,"Product added Successfully")
        return redirect('dashboard')
    return render(request,'accounts/products/add_products.html')
@login_required
@role_required(['admin'])
def list_products(request):
    products=Products.objects.all()
    return render(request,"accounts/products/view_products.html",{'products':products})
@login_required
@role_required(['admin'])
def update_product(request,id):
    product=get_object_or_404(Products,id=id)
    if request.method == 'POST':
        P_name=request.POST.get('p_name')
        price=request.POST.get('price')
        description=request.POST.get('description')
        p_image=request.FILES.get('p_image')
        updated_at=request.POST.get('updated_at')

        product.name=P_name
        product.price=price
        product.description=description
        product.created_at=updated_at

        if p_image:
            product.image=p_image

        product.save()
        messages.success(request,"Product Updated Successfully")
        return redirect('dashboard')

    return render(request,'accounts/products/update_products.html',{'product':product})

@role_required(['admin'])
def delete_product(request,id):
    product=get_object_or_404(Products,id=id)
    if request.method == "POST":
        product.delete()
        messages.success(request, "Product deleted successfully")
        return redirect("dashboard")

    return redirect('dashboard')
    