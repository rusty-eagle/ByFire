from django.urls import path
from . import views

urlpatterns = [
    #### Index
    path('', views.index, name='index'),

    #### System
    path('system', views.xdp_fastdrop, name='system'),
    path('system/host', views.system_host, name='system_host'),
    path('system/interfaces', views.system_interfaces, name='system_interfaces'),
    path('system/interfaces/edit/<int:iface_id>', views.system_interface_edit, name='system_interface_edit'),
    path('system/interfaces/wan', views.system_interfaces_wan, name='system_interfaces_wan'),
    path('system/interfaces/lan', views.system_interfaces_lan, name='system_interfaces_lan'),
    path('system/interfaces/apply', views.system_interfaces_apply, name='system_interfaces_apply'),
    path('system/interfaces/<str:iface>/<str:attr>', views.system_iface_attr),
    path('system/interfaces/txrx', views.system_interfaces_txrx, name='system_interfaces_txrx'),
    path('system/routes', views.system_routes, name='system_routes'),
    path('system/iptables', views.system_iptables, name='system_iptables'),
    path('system/iptables/add', views.system_iptables_add, name='system_iptables_add'),
    path('system/iptables/delete/<int:table_id>', views.system_iptables_delete, name='system_iptables_delete'),
    path('system/iptables/edit/<int:table_id>', views.system_iptables_edit, name='system_iptables_edit'),
    path('system/iptables/policy/edit/<int:table_id>', views.system_iptables_policy_edit, name='system_iptables_policy_edit'),
    path('system/iptables/reload', views.system_iptables_reload, name='system_iptables_reload'),
    path('system/logs', views.system_logs, name='system_logs'),
    path('system/interrupts/<str:ware>', views.system_interrupts, name='system_interrupts'),
    path('system/interrupts/update/<str:ware>', views.system_interrupts_update, name='system_interrupts_update'),

    #### Services
    path('service/dns', views.service_dns, name='service_dns'),
    path('service/dns/dhcp/build/reload', views.build_reload_dnsmasq, name='build_reload_dnsmasq'),
    path('service/dhcp', views.service_dhcp, name='service_dhcp'),
    path('service/dhcp/add', views.service_dhcp_add, name='service_dhcp_add'),
    path('service/dhcp/edit/<int:subnet_id>', views.service_dhcp_edit, name='service_dhcp_edit'),
    path('service/dhcp/delete/<int:subnet_id>', views.service_dhcp_delete, name='service_dhcp_delete'),
    path('service/blocklists', views.service_blocklists, name='service_blocklists'),
    path('service/blocklists/add', views.service_blocklists_add, name='service_blocklists_add'),
    path('service/blocklists/edit/<int:list_id>', views.service_blocklists_edit, name='service_blocklists_edit'),
    path('service/blocklists/delete/<int:list_id>', views.service_blocklists_delete, name='service_blocklists_delete'),

    #### Wireguard
    path('service/wireguard', views.service_wireguard, name='service_wireguard'),

    #### XDP
    path('xdp/fastdrop', views.xdp_fastdrop, name='xdp_fastdrop'),
]
