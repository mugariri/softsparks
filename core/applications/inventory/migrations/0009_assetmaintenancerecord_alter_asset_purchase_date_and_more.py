# Generated by Django 4.1.7 on 2023-04-02 17:39

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        (
            "inventory",
            "0008_alter_asset_purchase_date_alter_asset_received_date_and_more",
        ),
    ]

    operations = [
        migrations.CreateModel(
            name="AssetMaintenanceRecord",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("date", models.DateTimeField(auto_now_add=True)),
                ("reason", models.CharField(blank=True, max_length=255, null=True)),
                (
                    "description",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("upgrade", models.BooleanField(default=False)),
            ],
            options={
                "ordering": ["-date"],
            },
        ),
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 2, 19, 39, 7, 608710),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 2, 19, 39, 7, 608710),
                null=True,
            ),
        ),
        migrations.DeleteModel(
            name="AssetMaintenance",
        ),
        migrations.AddField(
            model_name="assetmaintenancerecord",
            name="asset",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="asset_maintained",
                to="inventory.asset",
            ),
        ),
        migrations.AddField(
            model_name="assetmaintenancerecord",
            name="external_agent",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="external_agent",
                to="inventory.assetsupplier",
            ),
        ),
        migrations.AddField(
            model_name="assetmaintenancerecord",
            name="internal_agent",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="internal_agent",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
