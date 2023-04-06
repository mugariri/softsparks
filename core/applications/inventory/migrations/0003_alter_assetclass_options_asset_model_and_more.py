# Generated by Django 4.1.7 on 2023-04-01 18:48

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0002_alter_asset_purchase_date_alter_asset_received_date"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="assetclass",
            options={
                "verbose_name": "Asset Classification",
                "verbose_name_plural": "Asset Classifications",
            },
        ),
        migrations.AddField(
            model_name="asset",
            name="model",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="asset",
            name="purchase_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 1, 20, 48, 32, 661167),
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="received_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(2023, 4, 1, 20, 48, 32, 661167),
                null=True,
            ),
        ),
    ]