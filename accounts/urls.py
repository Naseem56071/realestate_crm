from django.urls import path
from accounts import views

urlpatterns = [
    path("", views.contact_us, name="contact"),
    path('dashboard/contact-details/',
         views.contact_details, name="contact-details"),
    path('dashboard/edit-contact-details/<int:id>',
         views.edit_contact_details, name="admin.edit.contact-details"),
     path("dashboard/delete-contact-details/<int:id>",views.delete_contact_details,name="admin-delete-contact-details"),
    path("login/", views.login_view, name="login"),
    path('phone/login/',views.phone_login_view,name='phone.login'),
    path('phone/otp-verify/',views.verify_otp_view,name='phone.otp-verify'),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path(
        "admin/assign-permissions/",
        views.assign_permissions,
        name="assign_permissions"
    ),
    path('admin/dashboard/', views.admin_dashboard_view, name="admin.dashboard"),

    path("admin/delete/agent/associate/dahboard/<int:id>/",
         views.admin_deletes_agents_associates, name="admin.delete.agent.associate.dashboard"),
    path("create/agent/account/", views.create_agent,
         name="create.agent.account"),
    path("agent/dashboard/", views.agent_dashboard, name="agent.dashboard"),
    path("agent/dashboard/view/", views.agent_dashboard_view,
         name='agent.view.dashboard'),
    path("agent/delete/associates/dashboard/<int:id>/",
         views.agents_deleted_associates, name="agent.deletes.associates.dashboard"),
    path("create/associate/account",
         views.create_associate,
         name="create.associate.account",
         ),
    path("associate/dashboard/", views.associate_dashboard,
         name="associate.dashboard"),
    path("associate/index/tracking/dashboard/", views.associate_tracking_updates,
         name="associate.index.tracking.dashboard"),

    path("agent/view/dashboard/", views.agent_view_task,
         name="agent.view_task.dashboard"),

    path("agent/assign/task/dashboard/<str:name>/",
         views.agent_assign_task, name="agent.assign_lead.dashboard"),

    path("agent/updatetask/dashboard/<int:id>/",
         views.agent_update_task, name='agent.update_task.dashboard'),
    path("agent/deletetask/dashboard/<int:id>/",
         views.delete_task, name="agent.delete_task.dashboard"),

    path('associatetask/dashboard/', views.associate_view_task,
         name="associatetask.dashboard"),

    path('associate/updatetask/dashboard/<int:id>/',
         views.associate_update_task, name="associatetask.update.dashboard"),

    path('add_products/dashboard/', views.add_products,
         name="admin.add_products.dashboard"),
    path('list_products/dashboard/', views.list_products,
         name='admin.list_products/dashboard'),

    path('update_products/dashboard/<int:id>/', views.update_product,
         name="admin.update_products.dashboard"),
    path('delete_product/dashboard/<int:id>/', views.delete_product,
         name='admin.delete_product.dashboard'),

    path('admin/lead_details/dashboard/', views.lead_details,
         name="admin.lead_details.dashboard"),
         
    path('admin/delete_lead/dashboard/<int:id>/',
         views.admin_delete_lead, name="admin.delete.lead.dashboard"),
]
