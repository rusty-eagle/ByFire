# Generated by Django 3.1.1 on 2020-09-18 19:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('controlpanel', '0008_iptable_options'),
    ]

    operations = [
        migrations.AlterField(
            model_name='iptable',
            name='protocol',
            field=models.CharField(choices=[('all', 'All'), ('udp', 'Udp'), ('tcp', 'Tcp'), ('tcp/udp', 'Tcpudp'), ('icmp', 'Icmp')], default='tcp', max_length=10),
        ),
    ]