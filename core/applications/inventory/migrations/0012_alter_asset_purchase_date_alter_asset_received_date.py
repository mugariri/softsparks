# Generated by Django 4.1.7 on 2023-04-03 06:45

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0011_assettransfer_reason_assettransfer_type_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 3, 8, 45, 48, 594443),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 3, 8, 45, 48, 594443),
                null=True,
            ),
        ),
    ]
