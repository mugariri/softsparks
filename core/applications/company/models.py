from django.contrib.auth.models import User
from django.db import models
from tensorflow.python.autograph.operators.py_builtins import max_


# Create your models here.
class Branch(models.Model):
    name = models.CharField(max_length=255, blank=True, null=True)
    manager = models.OneToOneField(User, null=True, blank=True, on_delete=models.SET_NULL)
    description = models.CharField(max_length=255, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Department(models.Model):
    name = models.CharField(max_length=100)
    head = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='head')
    description = models.CharField(max_length=255, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class EmployeeStatus(models.Model):
    status = models.CharField(max_length=50, null=False, unique=True, blank=False)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.status

    class Meta:
        ordering = ['-created']
        verbose_name = 'Status'
        verbose_name_plural = 'Employee Status'


class Role(models.Model):
    ALLOWED_DUTY = (
        ("REGISTRATION", "ASSET REGISTRATION"),
        ("ALLOCATION", "ASSET ALLOCATION"),
        ("UPDATING", "ASSET UPDATING"),
        ("REPORTING", "ASSET REPORTING"),
        ("TRANSACTION", "ASSET TRANSACTION"),
    )
    name = models.CharField(max_length=50, null=True, blank=True, help_text='user role')
    allowed_duty = models.CharField(max_length=50, null=True, blank=True, help_text='duty')
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.name}'


class Employee(models.Model):
    STATES = (
        ("ACTIVE", "ACTIVE"),
        ("DISABLED", "DISABLED"),
        ("DELETED", "DELETED"),
        ("SUSPENDED", "SUSPENDED")
    )
    status = models.ForeignKey(EmployeeStatus, on_delete=models.SET_NULL, null=True, blank=True, help_text='status')
    state = models.CharField(max_length=15, null=True, blank=True, choices=STATES, help_text='state')
    user = models.OneToOneField(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="user")
    supervisor = models.OneToOneField(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="supervisor")
    branch = models.ForeignKey(Branch, null=True, blank=True, on_delete=models.SET_NULL, related_name="branch")
    title = models.CharField(max_length=50, null=True, blank=True)
    department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="department")
    employee_number = models.CharField(max_length=50, null=True, blank=True, unique=True,
                                       help_text="unique employee identification code")
    national_identity_number = models.CharField(max_length=50, null=True, blank=True, unique=True)
    cell_number = models.CharField(max_length=50, null=True, blank=True, unique=True, help_text='mobile number')
    extension = models.CharField(max_length=255, null=True, blank=True, help_text="office contact number")
    created = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created"]

    def __str__(self):
        return f'{self.user.first_name} {self.user.last_name}'

    def assign_a_supervisor(self, supervisor: User):
        self.supervisor = supervisor
        self.save()

    def add_to_department(self, department: Department):
        self.department = department
        self.save()

    def add_to_branch(self, branch: Branch):
        self.branch = branch
        self.save()

    def update_state(self, state: str):
        try:
            self.state = state
            self.save()
            return True
        except BaseException as e:
            return False, e

    def update_status(self, status: EmployeeStatus):
        self.status = status
        self.save()

