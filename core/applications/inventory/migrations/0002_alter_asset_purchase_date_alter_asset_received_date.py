# Generated by Django 4.1.7 on 2023-04-01 18:27

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 1, 20, 27, 48, 394986),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 1, 20, 27, 48, 394986),
                null=True,
            ),
        ),
    ]
