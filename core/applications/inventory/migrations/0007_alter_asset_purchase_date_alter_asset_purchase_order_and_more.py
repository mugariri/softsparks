# Generated by Django 4.1.7 on 2023-04-02 14:28

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0006_alter_assetsupplier_options_assetsupplier_email_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 2, 16, 28, 4, 674718),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="purchase_order",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 2, 16, 28, 4, 674718),
                null=True,
            ),
        ),
    ]
