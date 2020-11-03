from django.db import models

# Create your models here.

class System(models.Model):
    hostname = models.CharField(max_length=128,default="firewall")
    domain = models.CharField(max_length=128,default="lan")
    apply_iptables = models.BooleanField(default=True)
    apply_ipaddrs = models.BooleanField(default=False)
    apply_dnsmasq = models.BooleanField(default=False)
    timesync = models.BooleanField(default=True)
    time_server = models.CharField(max_length=128,default="ntp.ubuntu.com")
    timezone = models.CharField(max_length=75,default='America/Los_Angeles')
    unattended_upgrades = models.BooleanField(default=False)

class Iface(models.Model):
    name = models.CharField(max_length=20)

    dhcp4 = models.BooleanField(default=True)
    ipv4 = models.CharField(max_length=15, blank=True, null=True)
    ipv4_mask = models.CharField(max_length=15, blank=True, null=True)
    ipv4_gw = models.CharField(max_length=15, blank=True, null=True)
    ipv4_bc = models.CharField(max_length=15, blank=True, null=True)

    dhcp6 = models.BooleanField(default=False)
    ipv6 = models.CharField(max_length=23, blank=True, null=True)
    ipv6_mask = models.CharField(max_length=23, blank=True, null=True)
    ipv6_gw = models.CharField(max_length=23, blank=True, null=True)
    ipv6_bc = models.CharField(max_length=23, blank=True, null=True)

    mtu = models.IntegerField(default=1500)
    class Status(models.TextChoices):
        UP = 'up',
        DOWN = 'down'
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.UP,
    )
    mac = models.CharField(max_length=17)
    def __str__(self):
        return self.name

class wanlan(models.Model):
    wanlan = models.CharField(max_length=10)
    interface = models.ForeignKey(Iface, on_delete=models.CASCADE)

class DHCPSubnet(models.Model):
    # dhcp-range
    zone_name = models.CharField(max_length=15, default='internal')
    network = models.CharField(max_length=15, default='192.168.100.0')
    netmask = models.CharField(max_length=15, default='255.255.255.0')
    start = models.CharField(max_length=15, default='192.168.100.2')
    end = models.CharField(max_length=15, default='192.168.100.50')
    gateway = models.CharField(max_length=15, blank=True, null=True)
    lease_time = models.IntegerField(default=1)
    class MinuteHour(models.TextChoices):
        MIN = 'minute',
        HOUR = 'hour'
    min_hour = models.CharField(
        max_length=6,
        choices=MinuteHour.choices,
        default=MinuteHour.HOUR,
    )
### Static assign
### https://www.linux.com/topic/networking/dns-and-dhcp-dnsmasq/

class Table(models.TextChoices):
    FILTER = 'filter',
    NAT = 'nat',
    MANGLE = 'mangle',
    RAW = 'raw'
class Chain(models.TextChoices):
    INPUT = 'INPUT',
    OUTPUT = 'OUTPUT',
    FORWARD = 'FORWARD',
    ROUTING = 'ROUTING',
    PREROUTING = 'PREROUTING',
    POSTROUTING = 'POSTROUTING'

class IPTablePolicy(models.Model):
    table = models.CharField(
        max_length=6,
        choices=Table.choices,
        default=Table.FILTER,
    )
    chain = models.CharField(
        max_length=20,
        choices=Chain.choices,
        default=Chain.INPUT,
    )
    class DefaultPolicy(models.TextChoices):
        ACCEPT = 'ACCEPT',
        REJECT = 'REJECT',
        DROP = 'DROP'
    policy = models.CharField(
        max_length=6,
        choices=DefaultPolicy.choices,
        default=DefaultPolicy.ACCEPT,
    )

class IPTable(models.Model):
    active = models.BooleanField(default=True)
    removable = models.BooleanField(default=True)

    table = models.CharField(
        max_length=6,
        choices=Table.choices,
        default=Table.FILTER,
    )

    chain = models.CharField(
        max_length=20,
        choices=Chain.choices,
        default=Chain.INPUT,
    )

    class Protocol(models.TextChoices):
        ALL = 'all',
        UDP = 'udp',
        TCP = 'tcp',
        ICMP = 'icmp',
    protocol = models.CharField(
        max_length=10,
        choices=Protocol.choices,
        default=Protocol.TCP,
    )

    in_iface = models.ForeignKey(
        Iface,
        related_name='iface_ingress',
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
    )
    out_iface = models.ForeignKey(
        Iface,
        related_name='iface_egress',
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
    )

    source = models.CharField(max_length=26, null=True, blank=True)
    sport = models.CharField(max_length=15, null=True, blank=True)
    destination = models.CharField(max_length=26, null=True, blank=True)
    port = models.CharField(max_length=15, null=True, blank=True)
    options = models.CharField(max_length=50, null=True, blank=True)
    class Action(models.TextChoices):
        ACCEPT = 'ACCEPT',
        DROP = 'DROP',
        REJECT = 'REJECT',
        FORWARD = 'FORWARD',
        MASQUERADE = 'MASQUERADE',
    action = models.CharField(
        max_length=10,
        choices=Action.choices,
        default=Action.DROP,
    )

    class Match(models.TextChoices):
        STATE = 'state',
    match = models.CharField(
        max_length=20,
        choices=Match.choices,
        blank=True,
        null=True,
    )

    state = models.CharField(
        max_length=128,
        blank=True,
        null=True,
    )

    comment = models.CharField(
        max_length=128,
        blank=True,
        null=True,
    )

class DNS(models.Model):
    domain_needed = models.BooleanField(default=True) # domain-needed
    bogus_priv = models.BooleanField(default=True) # bogus-priv
    no_resolv = models.BooleanField(default=True) # no-resolv
    expand_hosts = models.BooleanField(default=True) # expand-hosts
    ##domain = models.BooleanField(default=True) # domain=lan
    ## System.domain
    ns_1 = models.CharField(max_length=23, blank=True, null=True) # server=1.1.1.1
    ns_2 = models.CharField(max_length=23, blank=True, null=True) # server=1.0.0.1
    ns_3 = models.CharField(max_length=23, blank=True, null=True)
    ## interface=enp6s0
    ## wanlan lan interface.name

class BlockList(models.Model):
    active = models.BooleanField(default=True)
    filename = models.CharField(max_length=512)
    url = models.CharField(max_length=512)

class WireguardInterface(models.Model):
    name = models.CharField(max_length=32) ## Interface name
    private_key = models.CharField(max_length=256)
    public_key = models.CharField(max_length=256)

class WireguardPeer(models.Model):
    interface = WireguardInterface
    name = models.CharField(max_length=32) ## Peer name
    public_key = models.CharField(max_length=256)
    endpoint = models.CharField(max_length=23)
    allows_ips = models.CharField(max_length=27)
    persistent_keepalive = models.CharField(max_length=3, default='21')
