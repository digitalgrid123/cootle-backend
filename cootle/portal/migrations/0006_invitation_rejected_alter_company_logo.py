# Generated by Django 5.0.6 on 2024-05-26 22:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('portal', '0005_user_fullname_invitation'),
    ]

    operations = [
        migrations.AddField(
            model_name='invitation',
            name='rejected',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='company',
            name='logo',
            field=models.ImageField(blank=True, null=True, upload_to='images/company-logos/'),
        ),
    ]
