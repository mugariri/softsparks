from django.contrib import admin

from core.applications.company.models import Employee


# Register your models here.
@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    search_fields = ['user__username', 'user__last_name', 'user__first_name', 'user__last_name']
    list_display = ['user', 'branch', 'department', 'cell_number']