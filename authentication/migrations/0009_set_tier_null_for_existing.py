# Generated migration - Alter tier field to allow NULL and set existing values to NULL

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0008_attorney_tier'),
    ]

    operations = [
        # First, alter the field to allow NULL
        migrations.AlterField(
            model_name='attorney',
            name='tier',
            field=models.CharField(blank=True, choices=[('one', 'Tier One'), ('two', 'Tier Two'), ('three', 'Tier Three'), ('four', 'Tier Four')], default=None, help_text='Attorney subscription tier', max_length=20, null=True),
        ),
        # Then set all existing values to NULL
        migrations.RunPython(
            lambda apps, schema_editor: apps.get_model('authentication', 'Attorney').objects.all().update(tier=None),
            lambda apps, schema_editor: apps.get_model('authentication', 'Attorney').objects.all().update(tier='one'),
        ),
    ]
