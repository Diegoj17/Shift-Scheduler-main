from django.contrib import admin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id","email","first_name","last_name","role","status","is_active","is_staff")
    search_fields = ("email","first_name","last_name")
    list_filter = ("role","status","is_active","is_staff")
