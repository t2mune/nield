nield
=====

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

##USAGE

    nield [-vh46inarft] [-p lock_file] [-s buffer_size] [-l log_file] [-L syslog_facility] [-d debug_file]

##OPTIONS

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

##FILES
    /usr/sbin/nield
    /var/run/nield.pid
    /var/log/nield.log
    /usr/share/man/man8/nield.8

