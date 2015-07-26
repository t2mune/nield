##![nield image](img/nield.jpg)

nield  (Network  Interface  Events  Logging  Daemon)  is  a tool to receive notifications from kernel through netlink socket, and generate logs related to interfaces, neighbor cache  (ARP,NDP),  IP  address  (IPv4,IPv6),  routing,  FIB rules, traffic control.

##Requirements
linux

##Download
###git command
    
    $ git clone https://github.com/t2mune/nield.git

##Install

    $ ./configure
    $ make
    # make install

##Usage

    nield [-vh46inarft] [-p lock_file] [-s buffer_size] [-l log_file] [-L syslog_facility] [-d debug_file]

##Options

    Standard options:

        -v     Displays the version and exit.

        -h     Displays the usage and exit.

        -p lock_file
               Specifies the lock file to use. Default is "/var/run/nield.pid", if not specified.

        -s buffer_size
               Specifies the maximum socket receive buffer in bytes.

    Logging options:
        It uses the log file "/var/log/nield.log", if neither "-l" nor "-L" specified.

        -l log_file
               Specifies the log file to use.

        -L syslog_facility
               Specifies the facility to use logging events via syslog.

               The standard syslog facilities are as follows:
                   auth, authpriv, cron, daemon, ftp, kern, lpr, mail, mark, news, security, syslog,
                   user, uucp, local0, local1, local2, local3, local4, local5, local6, local7

        -d debug_file
               Specifies the debug file to use.

    Event options:
        All events are received, if any event option not specified.

        -4     Logging events related to IPv4.

        -6     Logging events related to IPv6.

        -i     Logging events related to interfaces.

        -n     Logging events related to neigbour cache(ARP, NDP).

        -a     Logging events related to IP address.

        -r     Logging events related to routing.

        -f     Logging events related to fib rules.

        -t     Logging events related to traffic control.

##Files
    /usr/sbin/nield
    /var/run/nield.pid
    /var/log/nield.log
    /usr/share/man/man8/nield.8

##Examples
###Interface
When an interface was disabled by command:

    [2013-08-07 04:27:31.537101] interface eth0 state changed to disabled

When an interface has gone down:

    [2013-08-07 04:27:31.537125] interface eth0 state changed to down

When an interface was enabled by command:

    [2013-08-07 04:27:37.639079] interface eth0 state changed to enabled

When an interface has come up:

    [2013-08-07 04:27:40.267577] interface eth0 state changed to up

When link layer address of an interface changed:

    [2013-08-07 04:27:43.645661] interface eth0 link layer address changed from f6:af:fc:41:9e:7d to be:ee:bd:3d:22:68

When mtu of an interface changed:

    [2013-08-07 04:27:49.775200] interface eth0 mtu changed from 1500 to 1400

When a vlan interface was added:

    [2013-08-07 04:27:55.904868] interface added: name=eth0.100 link=eth0 lladdr=f6:af:fc:41:9e:7d mtu=1500 kind=vlan vid=100 state=disabled,linkdown

When a vlan interface was deleted:

    [2013-08-07 04:28:13.924831] interface deleted: name=eth0.100 link=eth0 lladdr=f6:af:fc:41:9e:7d mtu=1500 kind=vlan vid=100 state=disabled,linkdown

When a vxlan interface was added:

    [2013-08-07 06:30:08.938025] interface added: name=vxlan0 lladdr=9e:c5:83:a8:ea:00 mtu=1500 kind=vxlan vnid=100 local=192.168.1.100 group=224.0.0.100 state=disabled,linkdown

When a vxlan interface was deleted:

    [2013-08-07 06:30:27.378033] interface deleted: name=vxlan0 lladdr=9e:c5:83:a8:ea:00 mtu=1500 kind=vxlan vnid=100 local=192.168.1.100 group=224.0.0.100 state=disabled,linkdown

When a bridge interface was added:

    [2013-08-07 04:28:19.938136] interface added: name=br0 lladdr=f2:60:df:71:d0:ae mtu=1500 kind=bridge state=disabled,linkdown

When a tap interface was added:

    [2013-08-07 04:28:31.951485] interface added: name=tap0 lladdr=52:4e:47:b3:e2:00 mtu=1500 kind=tun state=disabled,linkdown

When a tap interface was attached to an ethernet bridge:

    [2013-08-07 04:28:37.958396] interface tap0 attached to bridge br0

When a tap interface was detached to an ethernet bridge:

    [2013-08-07 04:28:55.977159] interface tap0 detached from bridge br0

When a tap interface was deleted:

    [2013-08-07 04:29:01.983806] interface deleted: name=tap0 lladdr=52:4e:47:b3:e2:00 mtu=1500 kind=tun state=disabled,linkdown

When a bridge interface was deleted:

    [2013-08-07 04:29:14.006774] interface deleted: name=br0 lladdr=00:00:00:00:00:00 mtu=1500 kind=bridge state=disabled,linkdown

When a bonding interface was added:

    [2013-08-07 04:29:20.027673] interface added: name=bond0 lladdr=00:00:00:00:00:00 mtu=1500 kind=bond state=disabled,linkdown

When an interface was attached to a bonding interface:

    [2013-08-07 04:29:32.085061] interface eth0 attached to bonding bond0

When an interface was detached to a bonding interface:

    [2013-08-07 04:30:09.101576] interface eth0 detached from bonding bond0

When a bonding interface was deleted:

    [2013-08-07 04:30:27.644523] interface deleted: name=bond0 lladdr=00:00:00:00:00:00 mtu=1500 kind=bond state=disabled,linkdown

When a gre interface was added:

    [2013-08-07 04:30:33.678351] interface added: name=gre0 local=192.168.1.100 remote=192.168.2.100 mtu=1476 kind=gre state=disabled,linkdown

When a gre interface was deleted:

    [2013-08-07 04:30:51.698009] interface deleted: name=gre0 local=192.168.1.100 remote=192.168.2.100 mtu=1476 kind=gre state=disabled,linkdown

When a gretap interface was added:

    [2013-08-07 04:30:57.716615] interface added: name=gretap0 lladdr=a2:52:ec:ec:78:60 mtu=1462 kind=gretap local=192.168.1.100 remote=192.168.2.100 state=disabled,linkdown

When a gretap interface was deleted:

    [2013-08-07 04:31:15.736468] interface deleted: name=gretap0 lladdr=a2:52:ec:ec:78:60 mtu=1462 kind=gretap local=192.168.1.100 remote=192.168.2.100 state=disabled,linkdown

When an IPv4 tunnel interface(ipip,sit,isatap) was added:

    [2013-08-07 04:31:21.755082] interface added: name=iptnl0 local=192.168.1.100 remote=192.168.2.100 mtu=1480 state=disabled,linkdown

When an IPv4 tunnel interface(ipip,sit,isatap) was deleted:

    [2013-08-07 04:31:39.774847] interface deleted: name=iptnl0 local=192.168.1.100 remote=192.168.2.100 mtu=1480 kind=ipip state=disabled,linkdown

When an IPv6 tunnel interface(ip6ip6,ipip6) was added:

    [2013-08-07 04:32:58.112423] interface added: name=ip6tnl0 local=2001:db8:10::1 remote=2001:db8:20::1 mtu=1452 state=disabled,linkdown

When an IPv6 tunnel interface(ip6ip6,ipip6) was deleted:

    [2013-08-07 04:33:16.132706] interface deleted: name=ip6tnl0 local=2001:db8:10::1 remote=2001:db8:20::1 mtu=1452 kind=ip6tnl state=disabled,linkdown

###IPv4 ARP
When an ARP cache entry was created:

    [2013-08-07 04:33:28.157183] arp cache added: ip=192.168.1.2 mac=00:1b:8b:84:36:dc interface=eth0

When an ARP cache entry has expired:

    [2013-08-07 06:11:14.516780] arp cache deleted: ip=192.168.1.2 mac=00:1b:8b:84:36:dc interface=eth0

When an ARP cache entry was cleared by command:

    [2013-08-07 04:33:34.164063] arp cache invalidated: ip=192.168.1.2 mac=00:00:00:00:00:00 interface=eth0

When an ARP cache entry was unresolved:

    [2013-08-07 06:10:06.204374] arp cache unresolved: ip=192.168.1.2 mac=00:00:00:00:00:00 interface=eth0

When link layer address of an entry in the ARP cache table has changed:

    [2013-08-07 06:17:50.355827] arp cache changed: ip=192.168.1.2 mac=00:1b:8b:84:36:dc interface=eth0

###IPv6 NDP
When a NDP cache entry was created:

    [2013-08-07 04:34:28.221875] ndp cache added: ip=2001:db8::2 mac=00:1b:8b:84:36:dc interface=eth0

When a NDP cache entry has expired:

    [2013-08-07 06:20:00.084350] ndp cache deleted: ip=2001:db8::2 mac=00:1b:8b:84:36:dc interface=eth0

When a NDP cache entry was cleared by command:

    [2013-08-07 04:34:34.229066] ndp cache invalidated: ip=2001:db8::2 mac=00:00:00:00:00:00 interface=eth0

When a NDP cache entry was unresolved:

    [2013-08-07 04:34:34.229066] ndp cache unresolved: ip=2001:db8::2 mac=00:00:00:00:00:00 interface=eth0

When link layer address of an entry in the NDP cache table has changed:

    [2013-08-07 06:21:57.396102] ndp cache changed: ip=2001:db8::2 mac=00:1b:8b:84:36:dc interface=eth0

###IPv4 Address
When an IPv4 address was assigned:

    [2013-08-07 04:33:22.150078] ipv4 address added: interface=eth0 ip=192.168.1.1/24 socpe=global

When an IPv4 address was removed:

    [2013-08-07 04:34:04.195166] ipv4 address deleted: interface=eth0 ip=192.168.1.1/24 socpe=global

###IPv6 Address
When an IPv6 address was assigned:

    [2013-08-07 04:34:23.810337] ipv6 address added: interface=eth0 ip=2001:db8::1/64 socpe=global

When an IPv6 address was removed:

    [2013-08-07 04:35:04.262540] ipv6 address deleted: interface=eth0 ip=2001:db8::1/64 socpe=global

###IPv4 Route

When an IPv4 route was added:

    [2013-08-07 04:33:40.170235] ipv4 route added: destination=172.16.1.0/24 nexthop=192.168.1.2 interface=eth0 type=unicast protocol=boot table=main

When an IPv4 route was removed:

    [2013-08-07 04:33:46.176411] ipv4 route deleted: destination=172.16.1.0/24 nexthop=192.168.1.2 interface=eth0 type=unicast proto=boot table=main

###IPv6 Route
When an IPv6 route was added:

    [2013-08-07 04:34:40.235651] ipv6 route added: destination=2001:db8:1::/64 nexthop=2001:db8::2 interface=eth0 metric=1024 type=unicast protocol=boot table=main

When an IPv6 route was removed:

    [2013-08-07 04:34:46.242398] ipv6 route deleted: destination=2001:db8:1::/64 nexthop=2001:db8::2 interface=eth0 metric=1024 type=unicast proto=boot table=main

###IPv4 FIB Rule
When an IPv4 rule was added:

    [2013-08-07 04:35:22.281834] ipv4 rule added: from=192.168.1.0/24 table=unknown priority=32765 action=to_tbl

When an IPv4 rule was deleted:

    [2013-08-07 04:35:28.288220] ipv4 rule deleted: from=192.168.1.0/24 table=unknown priority=32765 action=to_tbl

###IPv6 FIB Rule

When an IPv6 rule was added:

    [2013-08-07 04:35:34.294521] ipv6 rule added: from=2001:db8:1::/64 table=unknown priority=16383 action=to_tbl

When an IPv6 rule was deleted:

    [2013-08-07 04:35:40.300824] ipv6 rule deleted: from=2001:db8:1::/64 table=unknown priority=16383 action=to_tbl

###Traffic Control
When a qdisc was added:

    [2013-08-07 04:37:46.502234] tc qdisc added: interface=eth0 parent=root classid=1: qdisc=htb rate2quantum=10 default-class=0x12

When a qdisc was deleted:

    [2013-08-07 04:37:52.516665] tc qdisc deleted: interface=eth0 parent=root classid=1: qdisc=htb rate2quantum=10 default-class=0x12

When a class was added:

    [2013-08-07 04:37:46.503530] tc class added: interface=eth0 parent=root classid=1:1 qdisc=htb rate=800.000(kbit/s) burst=1.562(Kbyte) ceil=1.600(Mbit/s) cburst=3.125(Kbyte) level=0 prio=0

When a class was deleted:

    [2013-08-07 04:37:52.515528] tc class deleted: interface=eth0 parent=root classid=1:1 qdisc=htb rate=800.000(kbit/s) burst=1.562(Kbyte) ceil=1.600(Mbit/s) cburst=3.125(Kbyte) level=0 prio=0

When a filter was added:

    [2013-08-07 04:40:28.814964] tc filter added: interface=eth0 handle=801::800 priority=10 protocol=ip filter=u32 classid=1:2 hash(table/bucket)=0x801/0x0
    [2013-08-07 04:40:28.814990] tc filter added: interface=eth0 handle=801::800 priority=10 protocol=ip filter=u32 flags=terminal offshift=0 nkeys=2 offmask=0x0000 off=0 offoff=0 hoff=0 hmask=0x00000000
    [2013-08-07 04:40:28.815007] tc filter added: interface=eth0 handle=801::800 priority=10 protocol=ip filter=u32 key=1 value=0xc0a86404 mask=0xffffffff offset=16 offmask=0x00000000
    [2013-08-07 04:40:28.815020] tc filter added: interface=eth0 handle=801::800 priority=10 protocol=ip filter=u32 key=2 value=0xc0a86403 mask=0xffffffff offset=12 offmask=0x00000000
    [2013-08-07 04:40:28.815099] tc filter added: interface=eth0 handle=801::800 priority=10 protocol=ip filter=u32 order=1 action=police index=1 rate=1.000(Mbit/s) burst=128.000(Kbyte) latency=0.000(us) exceed=drop

When a filter was deleted:

    [2013-08-07 04:40:34.830414] tc filter deleted: interface=eth0 handle=:: priority=10 protocol=ip filter=u32

When an action was added:

    [2013-08-07 04:40:10.769257] tc action added: order=1 action=nat index=20 from=192.168.1.0/24 to=192.168.2.1 direction=ingress
