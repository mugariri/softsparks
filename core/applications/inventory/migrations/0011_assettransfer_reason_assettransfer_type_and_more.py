# Generated by Django 4.1.7 on 2023-04-02 22:42

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "inventory",
            "0010_assettransfer_actioned_by_assettransfer_authorizer_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="assettransfer",
            name="reason",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="assettransfer",
            name="type",
            field=models.CharField(
                blank=True,
                choices=[("INTERNAL", "INTERNAL"), ("EXTERNAL", "EXTERNAL")],
                default="INTERNAL",
                max_length=50,
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 3, 0, 42, 58, 227243),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 3, 0, 42, 58, 227243),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="assettransfer",
            name="status",
            field=models.CharField(
                blank=True, default="AWAITING_APPROVAL", max_length=50, null=True
            ),
        ),
    ]
