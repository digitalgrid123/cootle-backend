# Generated by Django 5.0.6 on 2024-06-04 19:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('portal', '0008_alter_membership_unique_together'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='fullname',
            field=models.CharField(blank=True, max_length=30, null=True),
        ),
    ]