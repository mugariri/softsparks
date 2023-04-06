from rest_framework import serializers

from core.applications.inventory.models import Asset, AssetSupplier, AssetClass, AssetCategory, AssetTransfer


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = '__all__'


class AssetSupplierSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetSupplier
        fields = '__all__'


class AssetClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetClass
        fields = '__all__'


class AssetCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetCategory
        fields = '__all__'


class AssetTransferSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetTransfer
        fields = '__all__'
