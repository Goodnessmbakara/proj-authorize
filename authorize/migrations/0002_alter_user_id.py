# Generated by Django 5.0.2 on 2024-02-27 06:34

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authorize', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
        ),
    ]
