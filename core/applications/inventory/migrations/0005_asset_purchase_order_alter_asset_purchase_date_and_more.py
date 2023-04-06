# Generated by Django 4.1.7 on 2023-04-01 21:38

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0004_assetsupplier_asset_registered_by_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="asset",
            name="purchase_order",
            field=models.CharField(blank=True, max_length=255, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 1, 23, 38, 12, 954553),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 1, 23, 38, 12, 954553),
                null=True,
            ),
        ),
    ]
