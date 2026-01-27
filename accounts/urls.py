from django.urls import path
from accounts import views

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("create/agent/account/", views.create_agent, name="create.agent.account"),
    path("agent/dashboard/", views.agent_dashboard, name="agent.dashboard"),
    path(
        "create/associate/account",
        views.create_associate,
        name="create.associate.account",
    ),
    path("associate/dashboard/", views.associate_dashboard, name="associate.dashboard"),

    path("agent/view/dashboard/",views.agent_view_task,name="agent.view_task.dashboard"),

    path("agent/assigntask/dashboard/",views.agent_assign_task,name="agent.assign_lead.dashboard"),

    path("agent/updatetask/dashboard/<int:id>/",views.agent_update_task,name='agent.update_task.dashboard'),
    path("agent/deletetask/dashboard/<int:id>/",views.delete_task,name="agent.delete_task.dashboard"),

    path('associatetask/dashboard/',views.associate_view_task,name="associatetask.dashboard"),

    path('associate/updatetask/dashboard/<int:id>/',views.associate_update_task,name="associatetask.update.dashboard"),

    path('add_products/dashboard/',views.add_products,name="admin.add_products.dashboard"),
    path('list_products/dashboard/',views.list_products,name='admin.list_products/dashboard'),

    path('update_products/dashboard/<int:id>/', views.update_product,name="admin.update_products.dashboard"),
    path('delete_product/dashboard/<int:id>/', views.delete_product,name='admin.delete_product.dashboard'),
]

