# Generated by Django 4.1.7 on 2023-04-02 18:31

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("inventory", "0009_assetmaintenancerecord_alter_asset_purchase_date_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="assettransfer",
            name="actioned_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="actioned_by",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="assettransfer",
            name="authorizer",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="authorizer",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="assettransfer",
            name="status",
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 2, 20, 31, 12, 261547),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 2, 20, 31, 12, 261547),
                null=True,
            ),
        ),
    ]