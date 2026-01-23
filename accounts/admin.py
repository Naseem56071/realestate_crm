from django.contrib import admin
from accounts.models import User
# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display =['email', 'role', 'is_active','profile_image']
    
admin.site.register(User,UserAdmin)

