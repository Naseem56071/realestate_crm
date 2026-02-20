from django.urls import path
from accounts import views

urlpatterns = [
    path("", views.contact_us, name="contact"),

    path('dashboard/contact-details/',
         views.contact_details, name="contact-details"),

    path('dashboard/edit-contact-details/<int:id>',
         views.edit_contact_details, name="admin.edit.contact-details"),

    path("dashboard/delete-contact-details/<int:id>",
         views.delete_contact_details, name="admin-delete-contact-details"),

    path("login/", views.login_view, name="login"),
    path('forgot-password/', views.forgot_password, name="forgot_password"),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name="reset_password"),

    path('phone/login/', views.phone_login_view, name='phone.login'),

    path('phone/otp-verify/', views.verify_otp_view, name='phone.otp-verify'),

    path("logout/", views.logout_view, name="logout"),

    path("profile/upload-image/", views.upload_profile_image,
         name="upload_profile_image"),
    path('delete/profile/image/', views.delete_profile_image,
         name='delete.profile.image'),


    path("dashboard/", views.dashboard, name="dashboard"),

    path(
        "cus_admin/assign-permissions/",
        views.assign_permissions,
        name="assign_permissions"
    ),
    path('cus_admin/dashboard/', views.admin_dashboard_view, name="admin.dashboard"),

    path('actiavte/or/deactive/user/<int:id>', views.toggle_user_status,
         name='activate-ordeactivate.account'),
    path('cus_admin/update/agent/associate/<int:user_id>/',
         views.update_associate_and_agent, name='admin.updates.agent-associate'),

    path("cus_admin/delete/agent/associate/dahboard/<int:id>/",
         views.admin_deletes_agents_associates, name="admin.delete.agent.associate.dashboard"),

    path("create/agent/account/", views.admin_create_agent,
         name="create.agent.account"),

    path("agent/dashboard/", views.agent_dashboard, name="agent.dashboard"),

    path("agent/dashboard/view/", views.agent_dashboard_view,
         name='agent.view.dashboard'),

    path("agent/delete/associates/dashboard/<int:id>/",
         views.agents_deleted_associates, name="agent.deletes.associates.dashboard"),

    path("create/associate/account",
         views.agent_create_associate,
         name="create.associate.account",
         ),
    path('agent/update/associate/<int:id>/',
         views.update_associate, name='agent.update.associate'),
    path("associate/dashboard/", views.associate_dashboard,
         name="associate.dashboard"),

    path("associate/index/tracking/dashboard/", views.associate_tracking_updates,
         name="associate.index.tracking.dashboard"),

    path('associate/tracking/history/<int:associate_id>/<int:task_id>/',
         views.client_tracking_history, name="associate.tracking.history"),

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
         name='admin.list_products.dashboard'),

    path('update_products/dashboard/<int:id>/', views.update_product,
         name="admin.update_products.dashboard"),

    path('delete_product/dashboard/<int:id>/', views.delete_product,
         name='admin.delete_product.dashboard'),

    path('lead/details/dashboard/', views.list_lead_details,
         name="admin.lead_details.dashboard"),

    path('cus_admin/create-lead/dashbiard/', views.create_lead, name='admin.create-lead.dashbiard'
         ),

    path('cus_admin/delete_lead/dashboard/<int:id>/',
         views.admin_delete_lead, name="admin.delete.lead.dashboard"),

     path('check-out/product/<int:product_id>/',views.check_out_product,name='checkout_product'),

     path('create-payment/<int:product_id>/',views.create_payment,name='create_payment'),
     path('payment-verify/',views.payment_verify,name="payment_verify"),


]
