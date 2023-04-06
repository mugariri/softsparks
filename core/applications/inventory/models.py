import datetime

from django.contrib.auth.models import User
from django.db import models
from dns import serial


# Create your models here.
class AssetClass(models.Model):
    name = models.CharField(max_length=50, blank=False, null=False)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Asset Classifications"
        verbose_name = "Asset Classification"


class AssetCategory(models.Model):
    EXPECTANCY_UNIT = (
        ("DAYS", "days"),
        ("MONTHS", "months"),
        ("YEARS", "years"),
    )
    name = models.CharField(max_length=50, null=False, blank=False, unique=True)
    asset_class = models.ForeignKey(AssetClass, null=True, blank=False, related_name='aaset_class',
                                    on_delete=models.SET_NULL)
    manager = models.ForeignKey(User, null=True, blank=False, related_name='manager', on_delete=models.SET_NULL)
    expectancy = models.IntegerField(null=False, blank=False)
    expectancy_unit = models.CharField(max_length=10, default="YEARS", choices=EXPECTANCY_UNIT)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    def life_span(self):
        if self.expectancy_unit == "YEARS":
            return self.expectancy * 365
        elif self.expectancy_unit == "DAYS":
            return self.expectancy
        elif self.expectancy_unit == "MONTHS":
            return self.expectancy * 31
        else:
            return None

    class Meta:
        ordering = ['-created']
        verbose_name_plural = 'Asset Category'


class AssetSupplier(models.Model):
    name = models.CharField(max_length=50, unique=True, null=False, blank=True)
    email = models.EmailField(null=True, blank=True, unique=True)
    tel = models.CharField(max_length=50, null=True, blank=True)
    cell = models.CharField(max_length=50, null=True, blank=True)
    contact_person = models.CharField(max_length=50, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    description = models.CharField(max_length=50, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Asset Supplier"
        verbose_name_plural = "Asset Suppliers"


class Asset(models.Model):
    CONDITION = (
        ("GOOD", "GOOD"),
        ("FAIR", "FAIR"),
        ("BEST", "BEST"),
        ("N/A", "n/a"),
    )
    STATUS = (
        ("OBSOLETE", "obsolete"),
        ("ON_REPAIR", "repairs"),
        ("DISPOSED", "disposed"),
        ("ACTIVE", "active"),
        ("DISABLED", "disabled"),
    )
    tag = models.CharField(max_length=50, blank=True, null=True, unique=True)
    purchase_order = models.CharField(max_length=255, null=True, blank=True)
    registration = models.CharField(max_length=50, blank=True, null=True, unique=True)
    serial = models.CharField(max_length=50, null=False, blank=False, unique=True)
    category = models.ForeignKey(AssetCategory, null=True, blank=True, related_name='category',
                                 on_delete=models.SET_NULL)
    purchase_date = models.DateTimeField(null=True, blank=True, default=datetime.datetime.now())
    received_date = models.DateTimeField(null=True, blank=True, default=datetime.datetime.now())
    brand = models.CharField(max_length=255, null=True, blank=True)
    model = models.CharField(max_length=255, null=True, blank=True)
    colour = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    ram = models.CharField(max_length=255, null=True, blank=True)
    ip_address = models.CharField(max_length=255, null=True, blank=True)
    disk_size = models.CharField(max_length=255, null=True, blank=True)
    processor = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=255, null=True)
    current_user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='current')
    allocated_to = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='allocated')
    shared_resource = models.BooleanField(default=False, null=True, blank=True)
    shared_resource_location = models.CharField(max_length=255, null=True, blank=True)
    condition = models.CharField(max_length=25, null=True, blank=True, choices=CONDITION)
    price = models.DecimalField(max_digits=50, decimal_places=2, null=True, blank=True)
    conversion_rate = models.DecimalField(max_digits=50, decimal_places=2, null=True, blank=True)
    supplier = models.ForeignKey(AssetSupplier, null=True, blank=True, on_delete=models.SET_NULL)
    registered_by = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='registered_by', null=True)

    def __str__(self):
        return self.serial

    def current_depreciation(self):
        pass


class AssetTransfer(models.Model):
    STATUS = (
        ('AWAITING_APPROVAL', 'AWAITING APPROVAL'),
        ('APPROVED', 'APPROVED'),
        ('REVOKED', 'REVOKED'),
        ('RECEIVED', 'RECEIVED'),
        ('REJECTED', 'REJECTED'),
    )
    TYPE = (
        ('INTERNAL', 'INTERNAL'),
        ('EXTERNAL', 'EXTERNAL')
    )
    type = models.CharField(max_length=50, null=True, blank=True, choices=TYPE, default='INTERNAL')
    reference = models.CharField(max_length=255, null=True, blank=True, unique=True)
    asset = models.ForeignKey(Asset, related_name='asset', null=True, blank=True, on_delete=models.SET_NULL)
    sender = models.ForeignKey(User, related_name='sender', null=True, blank=True, on_delete=models.SET_NULL)
    authorizer = models.ForeignKey(User, related_name='authorizer', null=True, blank=True, on_delete=models.SET_NULL)
    recipient = models.ForeignKey(User, related_name='recipient', null=True, blank=True, on_delete=models.SET_NULL)
    actioned_by = models.ForeignKey(User, related_name='actioned_by', null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=50, null=True, blank=True, default='AWAITING_APPROVAL')
    reason = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.status}"

    def approve(self, authorizer: User):
        if self.status == 'AWAITING_APPROVAL' and self.recipient is not None and self.sender is not None and self.asset is not None:
            self.status = 'APPROVED'
            self.authorizer = authorizer
            self.save()
            return self
        else:
            return None

    def revoke(self, authorizer: User):
        self.status = 'REVOKED'
        self.authorizer = authorizer
        self.save()

    def acknowledge(self, acknowledged_by: User):
        if self.recipient is acknowledged_by:
            self.status = 'RECEIVED'
            self.actioned_by = acknowledged_by
            self.asset.allocated_to = acknowledged_by
            self.save()
            return self
        else:
            return None

    def reject(self, actioned_by: User):
        self.status = 'REJECTED'
        self.actioned_by = actioned_by
        self.save()
        return self


class AssetMaintenanceRecord(models.Model):
    asset = models.ForeignKey(Asset, related_name='asset_maintained', null=True, blank=True, on_delete=models.SET_NULL)
    date = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=255, null=True, blank=True)
    description = models.CharField(max_length=255, null=True, blank=True)
    upgrade = models.BooleanField(default=False)
    internal_agent = models.ForeignKey(User, related_name='internal_agent', null=True, blank=True,
                                       on_delete=models.SET_NULL)
    external_agent = models.ForeignKey(AssetSupplier, related_name='external_agent', null=True, blank=True,
                                       on_delete=models.SET_NULL)

    def __str__(self):
        return f'{self.asset} Maintenance'

    class Meta:
        ordering = ['-date']
