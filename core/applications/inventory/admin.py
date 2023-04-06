from django.contrib import admin

from core.applications.inventory.models import Asset, AssetCategory, AssetClass, AssetSupplier, AssetTransfer


# Register your models here.
@admin.register(AssetClass)
class AssetClassAdmin(admin.ModelAdmin):
    list_display = ['name', 'created']
    empty_value_display = '????'


@admin.register(AssetCategory)
class AssetCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'created', 'manager', 'expectancy', 'expectancy_unit']
    empty_value_display = '????'


@admin.register(AssetSupplier)
class AssetSupplierAdmin(admin.ModelAdmin):
    list_display = ['name', 'email', 'tel', 'cell']
    empty_value_display = '????'


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ['tag', 'serial', 'category', 'brand', 'model']
    empty_value_display = '????'


@admin.register(AssetTransfer)
class AssetTransferAdmin(admin.ModelAdmin):
    list_display = ['sender']
    empty_value_display = '????'
