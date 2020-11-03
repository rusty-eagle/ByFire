from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
import subprocess, os, requests, re, yaml
from . import models, forms

dnsmasq_prefix = "/etc/dnsmasq_blocklist."
iptables_bin = "/usr/sbin/iptables"
leasefile="/var/lib/dnsmasq/dnsmasq.leases"

def index(request):
    return render(request, 'index.html')

def system_interrupts(request, ware):
    return render(request, 'system/interrupts.html', {
        'type': ware,
    })
def system_interrupts_update(request, ware):
    if ware == 'hardware':
        irqs = subprocess.check_output(['/bin/cat', '/proc/interrupts'])
        payload = irqs.decode('utf-8')
    elif ware == 'software':
        irqs = subprocess.check_output(['/bin/cat', '/proc/softirqs'])
        payload = irqs.decode('utf-8')
    return JsonResponse({ 'data': payload })
def system_host(request):
    s = models.System.objects.first()

    if request.method == 'POST':
        form = forms.HostForm(request.POST, instance=s)
        if form.is_valid():
            form.save()
        else:
            return HttpResponse("ERROR")

        s = models.System.objects.first()
        ## Set unattended-upgrades
        if s.unattended_upgrades:
            subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'unattended-upgrades'])
        else:
            subprocess.run(['/usr/bin/systemctl', 'disable', '--now', 'unattended-upgrades'])

        ## Set timezone
        subprocess.run(['/usr/bin/timedatectl', 'set-timezone',  s.timezone])

        ## Set NTP server for systemd-timesyncd
		## to do :)

        ## Set systemd-timesyncd
        if s.timesync:
            subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'systemd-timesyncd'])
        else:
            subprocess.run(['/usr/bin/systemctl', 'disable', '--now', 'systemd-timesyncd'])

        ## Set flag so user can reload dnsmasq
        s.apply_dnsmasq = True
        s.save()

        return redirect('system_host')

    form = forms.HostForm(instance=s)

    get_users = subprocess.check_output(['/usr/bin/who'])
    users = get_users.decode('utf-8')

    get_processes = subprocess.check_output(['/bin/ps', 'fwwaux'])
    processes = get_processes.decode('utf-8')

    get_sys_info = subprocess.check_output(['/usr/bin/uname', '-a'])
    sys_info = get_sys_info.decode('utf-8')
    return render(request, 'system/host.html', {
        'form': form,
        'users': users,
        'processes': processes,
        'sys_info': sys_info,
        'system': s,
    })

def system_interfaces(request):
    s = models.System.objects.first()
    interfaces = models.Iface.objects.all()
    wan = models.wanlan.objects.get(wanlan='wan')
    lan = models.wanlan.objects.get(wanlan='lan')

    wanform = forms.WanLanForm(instance=wan)
    lanform = forms.WanLanForm(instance=lan)

    return render(request, 'system/interfaces.html', {
        'interfaces': interfaces,
        'wan': wan,
        'wanform': wanform,
        'lan': lan,
        'lanform': lanform,
        'iface_update': s.apply_ipaddrs,
    })

def system_interfaces_txrx(request):
    data = {}
    with open("/proc/net/dev", "r") as netf:
        for line in netf:
            if "Receiv" in line or "byte" in line:
                continue
            values = line.split()
            data[values[0][:-1]] = {
                'in': values[1],
                'out': values[9],
            }
    return JsonResponse(data)
def system_interface_edit(request, iface_id):
    iface = models.Iface.objects.get(id=iface_id)

    if request.method == 'POST':
        form = forms.InterfaceForm(request.POST, instance=iface)
        if form.is_valid():
            form.save()

        ## Apply interface data
        yaml_config = {
            'network': {
                'version': '2',
                'ethernets': {
                    iface.name: {}
                }
            }
        }
        if iface.dhcp4:
            yaml_config['network']['ethernets'][iface.name]['dhcp4'] = "yes"
        else:
            yaml_config['network']['ethernets'][iface.name]['dhcp4'] = "no"

        if iface.dhcp6:
            yaml_config['network']['ethernets'][iface.name]['dhcp6'] = "yes"
        else:
            yaml_config['network']['ethernets'][iface.name]['dhcp6'] = "no"

        if iface.ipv4 and iface.ipv4_mask:
            yaml_config['network']['ethernets'][iface.name]['addresses'] = '[' + iface.ipv4 \
                    + '/' + iface.ipv4_mask + ']'

        if iface.ipv4_gw:
            yaml_config['network']['ethernets'][iface.name]['gateway4'] = iface.ipv4_gw

        #if iface.ipv6 and iface.ipv6_mask:
            #yaml_config['network']['ethernets'][iface.name]['addresses'] = '[' + iface.ipv6 \
            #        + '/' + iface.ipv6_mask
        #if iface.ipv6_gw:
            #yaml_config['network']['ethernets'][iface.name]['gateway6'] = iface.ipv6_gw

        if iface.mtu:
            yaml_config['network']['ethernets'][iface.name]['mtu'] = iface.mtu

        output = yaml.dump(yaml_config).replace("'", "")
        with open("/etc/netplan/" + iface.name + ".yaml", 'w') as f:
            f.write(output)
            #yaml.dump(yaml_config, f)

        ## Do not change yet, but allow it to be changed
        s = models.System.objects.first()
        s.apply_ipaddrs = True
        s.save()

        return redirect('system_interfaces')

    form = forms.InterfaceForm(instance=iface)
    return render(request, 'system/iface_edit.html', {'form': form})

def system_interfaces_apply(request):
    s = models.System.objects.first()
    subprocess.run(['/usr/sbin/netplan', 'generate'])
    subprocess.run(['/usr/sbin/netplan', 'apply'])
    s.apply_ipaddrs = False
    s.save()
    return redirect('system_interfaces')

def system_iptables(request):
    policies = models.IPTablePolicy.objects.all()
    rules = models.IPTable.objects.all()
    firewall = models.System.objects.first()
    return render(request, 'system/iptables.html', {
        'policies': policies,
        'rules': rules,
        'system': firewall,
    })

def system_iptables_add(request):
    if request.method == 'POST':
        form = forms.IPTableForm(request.POST)
        if form.is_valid():
            form.save()
            s = models.System.objects.first()
            s.apply_iptables = True
            s.save()
        return redirect('system_iptables')

    form = forms.IPTableForm()
    return render(request, 'system/iptables_add.html', {
        'title': "IPTables Add",
        'form': form,
    })
def system_iptables_delete(request, table_id):
    iptable = models.IPTable.objects.get(id=table_id)
    iptable.delete()
    s = models.System.objects.first()
    s.apply_iptables = True
    s.save()
    return redirect('system_iptables')
def system_iptables_edit(request, table_id):
    iptable = models.IPTable.objects.get(id=table_id)

    if request.method == 'POST':
        form = forms.IPTableForm(request.POST, instance=iptable)
        if form.is_valid():
            form.save()
            s = models.System.objects.first()
            s.apply_iptables = True
            s.save()
        return redirect('system_iptables')

    form = forms.IPTableForm(instance=iptable)
    return render(request, 'system/iptables_edit.html', {
        'rule': iptable,
        'form': form,
    })
def system_iptables_policy_edit(request, table_id):
    policy = models.IPTablePolicy.objects.get(id=table_id)

    if request.method == 'POST':
        form = forms.IPTablePolicyForm(request.POST, instance=policy)
        if form.is_valid():
            form.save()
            s = models.System.objects.first()
            s.apply_iptables = True
            s.save()
        return redirect('system_iptables')
    form = forms.IPTablePolicyForm(instance=policy)
    return render(request, 'system/iptables_policy_edit.html', {
        'policy': policy,
        'form': form,
    })
def system_iptables_reload(request):
    s = models.System.objects.first()
    if s.apply_iptables:
        # Flush out stuff
        subprocess.run([iptables_bin,"-t", "filter", "-F", "INPUT"])
        subprocess.run([iptables_bin,"-t", "filter", "-F", "FORWARD"])
        subprocess.run([iptables_bin,"-t", "filter", "-F", "OUTPUT"])
        subprocess.run([iptables_bin,"-t", "nat", "-F", "PREROUTING"])
        subprocess.run([iptables_bin,"-t", "nat", "-F", "INPUT"])
        subprocess.run([iptables_bin,"-t", "nat", "-F", "OUTPUT"])
        subprocess.run([iptables_bin,"-t", "nat", "-F", "POSTROUTING"])
        subprocess.run([iptables_bin,"-t", "mangle", "-F", "PREROUTING"])
        subprocess.run([iptables_bin,"-t", "mangle", "-F", "INPUT"])
        subprocess.run([iptables_bin,"-t", "mangle", "-F", "OUTPUT"])
        subprocess.run([iptables_bin,"-t", "mangle", "-F", "FORWARD"])
        subprocess.run([iptables_bin,"-t", "mangle", "-F", "POSTROUTING"])
        subprocess.run([iptables_bin,"-t", "raw", "-F", "PREROUTING"])
        subprocess.run([iptables_bin,"-t", "raw", "-F", "OUTPUT"])

        # Apply policies
        policies = models.IPTablePolicy.objects.all()
        for policy in policies:
            subprocess.run([iptables_bin, '-t', policy.table.lower(), '-P', policy.chain.upper(), policy.policy.upper()])

        # Apply rules
        rules = models.IPTable.objects.all()
        for rule in rules:
            if not rule.active:
                continue

            cmd = [iptables_bin, '-t', rule.table, '-p', rule.protocol]

            if not rule.source is None:
                cmd.extend(['-s', rule.source])

            if not rule.destination is None:
                cmd.extend(['-d', rule.destination])

            if not rule.port is None:
                cmd.extend(['--dport', rule.port])

            cmd.extend(['-A', rule.chain])

            if not rule.in_iface is None:
                cmd.extend(['-i', rule.in_iface.name])

            if not rule.out_iface is None:
                cmd.extend(['-o', rule.out_iface.name])

            if not rule.options is None:
                cmd.extend([rule.options])

            if not rule.match is None:
                if rule.match == 'state':
                    if not rule.state is None:
                        cmd.extend(['-m', 'state', '--state', rule.state])

            if not rule.action is None:
                cmd.extend(['-j', rule.action])

            subprocess.run(cmd)

        ## Finally, save table, so interface state knows
        v4_rules = subprocess.check_output(['/sbin/iptables-save'])
        with open("/etc/iptables/rules.v4", 'w') as v4_file:
            v4_file.write(v4_rules.decode('utf-8'))

        v6_rules = subprocess.check_output(['/sbin/ip6tables-save'])
        with open("/etc/iptables/rules.v6", 'w') as v6_file:
            v6_file.write(v6_rules.decode('utf-8'))

        s.apply_iptables = False
        s.save()
    return redirect('system_iptables')

def system_interfaces_wan(request):
    if request.method == 'POST':
        wan = models.wanlan.objects.get(wanlan='wan')
        update_wan = forms.WanLanForm(request.POST, instance=wan)
        update_wan.save()
    return redirect('system_interfaces')
def system_interfaces_lan(request):
    if request.method == 'POST':
        lan = models.wanlan.objects.get(wanlan='lan')
        update_lan = forms.WanLanForm(request.POST, instance=lan)
        update_lan.save()
    return redirect('system_interfaces')

def system_routes(request):
    result = subprocess.check_output(['/usr/sbin/ip', 'route'])
    routes = result.decode('utf-8').split("\n")
    return render(request, 'system/routes.html', {
        #'title': "Routes",
        'routes': routes,
    })

def xdp_fastdrop(request):
    return render(request, 'xdp/fastdrop.html')

def system_logs(request):
    byfire = subprocess.check_output('journalctl -x -n100 -u byfire', shell=True)
    dnsmasq = subprocess.check_output('journalctl -x -n100 -u dnsmasq', shell=True)

    return render(request, 'system/logs.html', {
        'byfire': byfire.decode('utf-8'),
        'dnsmasq': dnsmasq.decode('utf-8'),
    })

def system_iface_attr(request, iface, attr):
    payload = ""

    if attr == 'mac':
        for mac in open("/sys/class/net/" + iface + "/address"):
            payload = mac.strip()

    if attr == 'mtu':
        for mtu in open("/sys/class/net/" + iface + "/mtu"):
            payload = mtu.strip()

    if attr == 'ipv4':
        addrs = subprocess.check_output(['/usr/sbin/ip', '-4', 'addr', 'show', iface])
        lines = addrs.decode('utf-8').split('\n')
        for line in lines:
            if re.search("inet ", line):
                values = re.split('\s+', line)
                parts = values[2].split('/')
                payload = parts[0]

    if attr == 'ipv4_mask':
        addrs = subprocess.check_output(['/usr/sbin/ip', '-4', 'addr', 'show', iface])
        lines = addrs.decode('utf-8').split('\n')
        for line in lines:
            if re.search("inet ", line):
                values = re.split('\s+', line)
                parts = values[2].split('/')
                payload = '/' + parts[1]

    if attr == 'ipv4_bc':
        addrs = subprocess.check_output(['/usr/sbin/ip', '-4', 'addr', 'show', iface])
        lines = addrs.decode('utf-8').split('\n')
        for line in lines:
            if re.search("inet ", line):
                values = re.split('\s+', line)
                payload = values[4]

    if attr == 'ipv4_gw':
        rte = subprocess.check_output(['/usr/sbin/ip', '-4', 'route', 'show', 'default'])
        values = re.split('\s+', rte.decode('utf-8'))
        payload = values[2]

    if attr == 'ipv6':
        addrs = subprocess.check_output(['/usr/sbin/ip', '-6', 'addr', 'show', iface])
        lines = addrs.decode('utf-8').split('\n')
        for line in lines:
            if re.search("inet6 ", line):
                values = re.split('\s+', line)
                parts = values[2].split('/')
                payload = parts[0]

    if attr == 'ipv6_mask':
        addrs = subprocess.check_output(['/usr/sbin/ip', '-6', 'addr', 'show', iface])
        lines = addrs.decode('utf-8').split('\n')
        for line in lines:
            if re.search("inet6 ", line):
                values = re.split('\s+', line)
                parts = values[2].split('/')
                payload = '/' + parts[1]

    if attr == 'ipv6_bc':
        addrs = subprocess.check_output(['/usr/sbin/ip', '-6', 'addr', 'show', iface])
        lines = addrs.decode('utf-8').split('\n')
        for line in lines:
            if re.search("inet6 ", line):
                values = re.split('\s+', line)
                payload = values[4]

    json = {
        'data': payload,
    }
    return JsonResponse(json)

def service_dns(request):
    sys = models.System.objects.first()
    dns = models.DNS.objects.first()

    if request.method == 'POST':
        form = forms.DNSForm(request.POST, instance=dns)
        if form.is_valid():
            form.save()

        sys.apply_dnsmasq = True
        sys.save()

        return redirect('service_dns')

    form = forms.DNSForm(instance=dns)
    return render(request, 'service/dns.html', {
        'form': form,
        'system': sys,
    })

def build_reload_dnsmasq(request):
    sys = models.System.objects.first()
    dns = models.DNS.objects.first()
    subnets = models.DHCPSubnet.objects.all()
    lan = models.wanlan.objects.get(wanlan='lan')
    lists = models.BlockList.objects.all()

    ## set hostname
    hostname = sys.hostname + "." + sys.domain
    subprocess.run(["/usr/bin/hostnamectl", "set-hostname", hostname])

    hosts_file = ""
    match = False
    with open("/etc/hosts", 'r') as etc_hosts:
        for line in etc_hosts:
            if lan.interface.ipv4 and lan.interface.ipv4 in line:
                hosts_file += lan.interface.ipv4 + " " + hostname + "\n"
                match = True
            elif lan.interface.ipv6 and lan.interface.ipv6 in line:
                hosts_file += lan.interface.ipv6 + " " + hostname + "\n"
                match = True
            else:
                hosts_file += line
    if match:
        with open("/etc/hosts", 'w') as etc_hosts:
            etc_hosts.write(hosts_file)
    else:
        with open("/etc/hosts", 'a') as etc_hosts:
            if lan.interface.ipv4:
                etc_hosts.write(lan.interface.ipv4 + " " + hostname + "\n")
            if lan.interface.ipv6:
                etc_hosts.write(lan.interface.ipv6 + " " + hostname + "\n")

    ## build
    config = "interface=" + lan.interface.name + "\n"
    config += "domain=" + sys.domain + "\n"

    if dns.domain_needed:
        config += "domain-needed\n"

    if dns.bogus_priv:
        config += "bogus-priv\n"

    if dns.no_resolv:
        config += "no-resolv\n"

    if dns.expand_hosts:
        config += "expand-hosts\n"

    if dns.ns_1:
        config += "server=" + dns.ns_1 + "\n"

    if dns.ns_2:
        config += "server=" + dns.ns_2 + "\n"

    if dns.ns_3:
        config += "server=" + dns.ns_3 + "\n"

    for subnet in subnets:
        config += "dhcp-range=" + subnet.zone_name
        config += "," + subnet.start
        config += "," + subnet.end
        config += ",%d" % subnet.lease_time
        if subnet.min_hour == models.DHCPSubnet.MinuteHour.HOUR:
            config += "h"
        elif subnet.min_hour == models.DHCPSubnet.MinuteHour.MIN:
            config += "m"
        config += "\n"

    ## Add DHCP lease file
    config += "dhcp-leasefile=" + leasefile + "\n"

    ## Add in the ad blocker
    for l in lists:
        if l.active:
            config += "conf-file=" + dnsmasq_prefix + l.filename + "\n"

    with open("/etc/dnsmasq.conf", "w") as config_file:
        config_file.write(config)

    ## restart
    subprocess.run(["/usr/bin/systemctl", "restart", "dnsmasq"])

    sys.apply_dnsmasq = False
    sys.save()

    ## redirect
    return redirect('service_dns')

def service_dhcp(request):
    s = models.System.objects.first()

    subnets = models.DHCPSubnet.objects.all()

    return render(request, 'service/dhcp.html', {
        'subnets': subnets,
        'system': s,
    })
def service_dhcp_add(request):
    if request.method == 'POST':
        form = forms.DHCPSubnetForm(request.POST)
        if form.is_valid():
            form.save()

        s = models.System.objects.first()
        s.apply_dnsmasq = True
        s.save()

        return redirect('service_dhcp')

    form = forms.DHCPSubnetForm()
    return render(request, 'service/dhcp_add.html', {
        'form': form,
    })

def service_dhcp_delete(request, subnet_id):
    s = models.System.objects.first()

    subnet = models.DHCPSubnet.objects.get(id=subnet_id)
    subnet.delete()

    s.apply_dnsmasq = True
    s.save()

    return redirect('service_dhcp')

def service_dhcp_edit(request, subnet_id):
    subnet = models.DHCPSubnet.objects.get(id=subnet_id)

    if request.method == 'POST':
        form = forms.DHCPSubnetForm(request.POST, instance=subnet)
        if form.is_valid():
            form.save()
    
        s = models.System.objects.first()
        s.apply_dnsmasq = True
        s.save()

        return redirect('service_dhcp')

    form = forms.DHCPSubnetForm(instance=subnet)
    return render(request, 'service/dhcp_edit.html', {
        'form': form,
    })

def service_blocklists(request):
    sys = models.System.objects.first()
    lists = models.BlockList.objects.all()
    return render(request, 'service/blocklists.html', {
        'lists': lists,
        'system': sys,
    })

def service_blocklists_add(request):
    if request.method == 'POST':
        form = forms.BlockListForm(request.POST)
        if form.is_valid():
            form.save()

        new_filename = request.POST.get('filename')
        new_url = request.POST.get('url')
        resp = requests.get(new_url)
        with open(dnsmasq_prefix + new_filename, "w") as f:
            f.write(resp.content.decode('utf-8'))

        sys = models.System.objects.first()
        sys.apply_dnsmasq = True
        sys.save()

        return redirect('service_blocklists')

    form = forms.BlockListForm()
    return render(request, 'service/blocklists_add.html', {
        'form': form,
    })

def service_blocklists_delete(request, list_id):
    l = models.BlockList.objects.get(id=list_id)
    os.remove(dnsmasq_prefix + l.filename)
    l.delete()

    sys = models.System.objects.first()
    sys.apply_dnsmasq = True
    sys.save()

    return redirect('service_blocklists')

def service_blocklists_edit(request, list_id):
    l = models.BlockList.objects.get(id=list_id)

    if request.method == 'POST':
        get_form = False
        new_filename = request.POST.get('filename')
        new_url = request.POST.get('url')
        if not new_url is None:
            if new_url != l.url:
                get_form = True

        form = forms.BlockListForm(request.POST, instance=l)
        if form.is_valid():
            form.save()

        if get_form:
            resp = requests.get(new_url)
            with open(dnsmasq_prefix + new_filename, "w") as f:
                f.write(resp.content.decode('utf-8'))

        sys = models.System.objects.first()
        sys.apply_dnsmasq = True
        sys.save()

        return redirect('service_blocklists')

    form = forms.BlockListForm(instance=l)
    return render(request, 'service/blocklists_edit.html', {
        'form': form,
    })

def service_wireguard(request):
    return render(request, 'service/wireguard.html')
