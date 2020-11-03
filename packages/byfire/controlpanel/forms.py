from django import forms
from django.forms import ModelForm
from . import models

class HostForm(ModelForm):
    class Meta:
        model = models.System
        fields = [
            'hostname',
            'domain',
            'timesync',
            'time_server',
            'timezone',
            'unattended_upgrades',
        ]

class InterfaceForm(ModelForm):
    class Meta:
        model = models.Iface
        fields = [
            'name',
            'dhcp4',
            'ipv4',
            'ipv4_mask',
            'ipv4_gw',
            'ipv4_bc',
            'dhcp6',
            'ipv6',
            'ipv6_mask',
            'ipv6_gw',
            'ipv6_bc',
            'mtu',
            'status',
            'mac'
        ]

class WanLanForm(ModelForm):
    class Meta:
        model = models.wanlan
        fields = ['interface']
class IPTablePolicyForm(ModelForm):
    class Meta:
        model = models.IPTablePolicy
        fields = [
            #'table',
            #'chain',
            'policy'
        ]
class IPTableForm(ModelForm):
    class Meta:
        model = models.IPTable
        fields = [
            'active',
            'table',
            'chain',
            'protocol',
            'in_iface',
            'out_iface',
            'source',
            'sport',
            'destination',
            'port',
            'match',
            'state',
            'options',
            'action',
            'comment',
        ]

class DNSForm(ModelForm):
    class Meta:
        model = models.DNS
        fields = [
            'domain_needed',
            'bogus_priv',
            'expand_hosts',
            'ns_1',
            'ns_2',
            'ns_3'
        ]
class DHCPSubnetForm(ModelForm):
    class Meta:
        model = models.DHCPSubnet
        fields = [
            'zone_name',
            'network',
            'netmask',
            'start',
            'end',
            'gateway',
            'lease_time',
            'min_hour'
        ]

class BlockListForm(ModelForm):
    class Meta:
        model = models.BlockList
        fields = [
            'filename',
            'url',
            'active',
        ]
