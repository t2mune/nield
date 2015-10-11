/*
 * nield.c - evnent receiver
 * Copyright (C) 2015 Tetsumune KISO <t2mune@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#define SYSLOG_NAMES
#include "nield.h"

static int log_opts;
static int facility;
static int msg_opts;
static int lock_fd;
static int rcv_buflen;
static char lock_file[MAX_STR_SIZE] = LOCK_FILE;
static char log_file[MAX_STR_SIZE];
static char dbg_file[MAX_STR_SIZE];
volatile int sigterm_received = 0;
volatile int sigint_received = 0;

/*
 * main function
 */
int main(int argc, char *argv[])
{
    int rt_sock = -1, xfrm_sock = -1, ret;
    unsigned rt_groups, xfrm_groups;

    /* set option */
    ret = set_options(argc, argv);
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 0, ret);

    /* open log file */
    ret = open_log(log_file);
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 0, ret);

    /* open debug file */
    if(log_opts & L_DEBUG) {
        ret = open_dbg(dbg_file);
        if(ret < 0)
            close_exit(rt_sock, xfrm_sock, 0, ret);
    }

    /* create lock file */
    ret = open_lock();
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 0, ret);

    /* set signal handlers */
    ret = set_signal_handlers();
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 0, ret);

    /* initizlize daemon */
    ret = init_daemon();
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 0, ret);

    rec_log("info: nield %s started(PID: %ld)", VERSION, (long)getpid());

    /* write pid to lock file */
    ret = write_lock();
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 0, ret);

    /* open netlink socket to create list */
    rt_groups = 0;
    rt_sock = open_netlink_socket(rt_groups, NETLINK_ROUTE);
    if(rt_sock < 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    /* request interface list */
    ret = send_request(rt_sock, RTM_GETLINK, AF_UNSPEC);
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    /* receive interface list */
    ret = recv_reply(rt_sock, RTM_GETLINK);
    if(ret != 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    /* request bridge interface list */
    ret = send_request(rt_sock, RTM_GETLINK, AF_BRIDGE);
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    /* receive bridge interface list */
    ret = recv_reply(rt_sock, RTM_GETLINK);
    if(ret != 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    /* request neighbor cache list */
    ret = send_request(rt_sock, RTM_GETNEIGH, AF_UNSPEC);
    if(ret < 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    /* receive & create interface list */
    ret = recv_reply(rt_sock, RTM_GETNEIGH);
    if(ret != 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    /* close socket */
    close(rt_sock);

    /* set rtnetlink multicast groups */
    rt_groups = set_rt_groups();
    rt_sock = open_netlink_socket(rt_groups, NETLINK_ROUTE);
    if(rt_sock < 0)
        close_exit(rt_sock, xfrm_sock, 1, ret);

    xfrm_groups = set_xfrm_groups();
    xfrm_sock = open_netlink_socket(xfrm_groups, NETLINK_XFRM);
    if(xfrm_sock < 0)
        close_exit(xfrm_sock, xfrm_sock, 1, ret);

    /* recevie events */
    ret = recv_events(rt_sock, xfrm_sock);

    close_exit(rt_sock, xfrm_sock, 1, ret);

    return(0);
}

/*
 * close a rtnetlink socket and a debug file, and then exit
 */
void close_exit(int rt_sock, int xfrm_sock, int log_flag, int ret)
{
    /* close file descriptor */
    if(rt_sock > 0)
        close(rt_sock);

    if(xfrm_sock > 0)
        close(xfrm_sock);

    /* close debug file */
    if(log_opts & L_DEBUG)
        close_dbg();
    
    if(log_flag)
        rec_log("info: nield %s terminated(PID: %ld)", VERSION, getpid());

    /* close log file */
    close_log();

    /* close lock file */
    close_lock();

    exit(ret);
}

/*
 * set options
 */
int set_options(int argc, char *argv[])
{
    int opt;

    /* set default value */
    strcpy(log_file, LOG_FILE_DEFAULT);
    strcpy(dbg_file, DEBUG_FILE_DEFAULT);

    /* parse options */
    while((opt = getopt(argc, argv, "vhp:l:s:L:d:46inarftx")) != EOF) {
        switch(opt) {
            case 'v':
                fprintf(stderr, "version: %s\n", VERSION);
                return(-1);
            case 'h':
                fprintf(stderr, "usage: nield %s\n", NIELD_USAGE);
                return(-1);
            case 'p':
                strncpy(lock_file, optarg, MAX_STR_SIZE);
                break;
            case 'l':
                if(strlen(optarg) < MAX_STR_SIZE) {
                    strcpy(log_file, optarg);
                } else {
                    fprintf(stderr, "error: %s: log file path is longer than %d byte\n",
                        __func__, MAX_STR_SIZE);
                    return(-1);
                }
                log_opts |= L_LOCAL;
                break;
            case 'L':
                if(strlen(optarg) < MAX_STR_SIZE) {
                    facility = set_facility(optarg);
                    if(facility < 0) {
                        fprintf(stderr, "error: %s: unknown syslog facility \"%s\"\n",
                            __func__, optarg);
                        return(-1);
                    }
                } else {
                    fprintf(stderr, "error: %s: syslog facility is longer than %d byte\n",
                        __func__, MAX_STR_SIZE);
                    return(-1);
                }
                log_opts |= L_SYSLOG;
                break;
            case 'd':
                if(strlen(optarg) < MAX_STR_SIZE) {
                    strcpy(dbg_file, optarg);
                } else {
                    fprintf(stderr, "error: %s: debug file path is longer than %d byte\n",
                        __func__, MAX_STR_SIZE);
                    return(-1);
                }
                log_opts |= L_DEBUG;
                break;
            case 's':
                if(strlen(optarg) < MAX_STR_SIZE) {
                    rcv_buflen = atoi(optarg);
                } else {
                    fprintf(stderr, "error: %s: receive buffer size is longer than %d byte\n",
                        __func__, MAX_STR_SIZE);
                    return(-1);
                }
                break;
            case '4':
                msg_opts |= M_IPV4;
                break;
            case '6':
                msg_opts |= M_IPV6;
                break;
            case 'i':
                msg_opts |= M_LINK;
                break;
            case 'n':
                msg_opts |= M_NEIGH;
                break;
            case 'a':
                msg_opts |= M_IFADDR;
                break;
            case 'r':
                msg_opts |= M_ROUTE;
                break;
            case 'f':
                msg_opts |= M_RULE;
                break;
            case 't':
                msg_opts |= M_TC;
                break;
            case 'x':
                msg_opts |= M_XFRM;
            default:
                return(-1);
        }
    }

    if(!(log_opts & L_LOCAL) && !(log_opts & L_SYSLOG)) {
        log_opts |= L_LOCAL;
    }

    return(0);
}

/*
 * get logging options
 */
int get_log_opts(void)
{
    return(log_opts);
}

/*
 * get message options
 */
int get_msg_opts(void)
{
    return(msg_opts);
}

/*
 * set syslog facility
 */
int set_facility(char *facility_name)
{
    int i;

    for(i = 0; facilitynames[i].c_val >= 0; i++) {
        if(!strcmp(facility_name, facilitynames[i].c_name)) {
            break;
        }
    }

    return(facilitynames[i].c_val);
}

/*
 * get syslog facility
 */
int get_facility(void)
{
    return(facility);
}

/*
 * create a lock file
 */
int open_lock(void)
{
    int err;
    char pid_str[16];

    if((lock_fd = open(lock_file, O_RDONLY, 0)) > 0) {
        err = read(lock_fd, pid_str, sizeof(pid_str)-1);
        if(err < 0) {
            fprintf(stderr, "error: %s: read(): %s\n", __func__, strerror(errno));
            fprintf(stderr, "error: %s: can't read pid file\n", __func__);
            close(lock_fd);
            lock_fd = 0;
            return(-1);
        }
        pid_str[err] = '\0';

        if(kill((pid_t)atol(pid_str), 0) == 0) {
            fprintf(stderr, "error %s: nield already running(PID: %ld)\n", __func__, atol(pid_str));
            close(lock_fd);
            lock_fd = 0;
            return(-1);
        }
        close(lock_fd);

        lock_fd = open(lock_file, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    } else {
        lock_fd = open(lock_file, O_CREAT|O_EXCL|O_WRONLY, 0644);
    }

    if(lock_fd < 0) {
        fprintf(stderr, "error %s: open(): %s\n", __func__, strerror(errno));
        fprintf(stderr, "error %s: can't create lock file\n", __func__);
        return(-1);
    }

    return(0);
}

/*
 * write PID to a lock file
 */
int write_lock(void)
{
    char pid_str[16];
    int ret;

    snprintf(pid_str, sizeof(pid_str), "%ld\n", (long)getpid());
    ret = write(lock_fd, pid_str, strlen(pid_str));
    if(ret < 0)
        fprintf(stderr, "error %s: write(): %s\n", __func__, strerror(errno));

    return(ret);
}

/*
 * close a lock file
 */
void close_lock(void)
{
    if(lock_fd) {
        close(lock_fd);
        unlink(lock_file);
    }
}

/*
 * initialize daemon
 */
int init_daemon(void)
{
    /* check user */
    if(getuid() != 0) {
        fprintf(stderr, "error: %s: only root can run nield\n", __func__);
        return(-1);
    }

    /* change root directory */
    if(chdir("/") == EOF) {
        fprintf(stderr, "error: %s: can't change root directory\n", __func__);
        fprintf(stderr, "error: %s: chdir(): %s\n", __func__, strerror(errno));
        return(-1);
    }

    /* detach from controlling terminal */
    if(daemon(0, 0) < 0) {
        fprintf(stderr, "error: %s: can't detach terminal\n", __func__);
        fprintf(stderr, "error: %s: daemon(): %s\n", __func__, strerror(errno));
        return(-1);
    }

    return(0);
}

/*
 * set signal handlers(SIGTERM, SIGINT)
 */
int set_signal_handlers(void)
{
    struct sigaction sigterm_act, sigint_act, sigusr1_act, sigusr2_act;

    /* set SIGTERM handler */
    sigterm_act.sa_handler = sigterm_handler;
    if(sigfillset(&sigterm_act.sa_mask) < 0) {
        fprintf(stderr, "error: %s: sigfillset(): %s\n", __func__, strerror(errno));
        return(-1);
    }
    sigterm_act.sa_flags = 0;

    if(sigaction(SIGTERM, &sigterm_act, 0) < 0) {
        fprintf(stderr, "error: %s: sigaction(): %s\n", __func__, strerror(errno));
        return(-1);
    }

    /* set SIGINT handler */
    sigint_act.sa_handler = sigint_handler;
    if(sigfillset(&sigint_act.sa_mask) < 0) {
        fprintf(stderr, "error: %s: sigfillset(): %s\n", __func__, strerror(errno));
        return(-1);
    }
    sigint_act.sa_flags = 0;

    if(sigaction(SIGINT, &sigint_act, 0) < 0) {
        fprintf(stderr, "error: %s: sigaction(): %s\n", __func__, strerror(errno));
        return(-1);
    }

    /* set SIGUSR1 handler */
    sigusr1_act.sa_handler = sigusr1_handler;
    if(sigfillset(&sigusr1_act.sa_mask) < 0) {
        fprintf(stderr, "error: %s: sigfillset(): %s\n", __func__, strerror(errno));
        return(-1);
    }
    sigusr1_act.sa_flags = 0;

    if(sigaction(SIGUSR1, &sigusr1_act, 0) < 0) {
        fprintf(stderr, "error: %s: sigaction(): %s\n", __func__, strerror(errno));
        return(-1);
    }

    /* set SIGUSR2 handler */
    sigusr2_act.sa_handler = sigusr2_handler;
    if(sigfillset(&sigusr2_act.sa_mask) < 0) {
        fprintf(stderr, "error: %s: sigfillset(): %s\n", __func__, strerror(errno));
        return(-1);
    }
    sigusr2_act.sa_flags = 0;

    if(sigaction(SIGUSR2, &sigusr2_act, 0) < 0) {
        fprintf(stderr, "error: %s: sigaction(): %s\n", __func__, strerror(errno));
        return(-1);
    }

    return(0);
}
        
/*
 * signal handler for SIGTERM
 */
void sigterm_handler(int sig)
{
    rec_log("info: SIGTERM called(PID: %ld)", (long)getpid());
    sigterm_received = 1;
}

/*
 * signal handler for SIGINT
 */
void sigint_handler(int sig)
{
    rec_log("info: SIGINT called(PID: %ld)", (long)getpid());
    sigint_received = 1;
}

/*
 * signal handler for SIGUSR1
 */
void sigusr1_handler(int sig)
{
    rec_log("info: SIGUSR1 called(PID: %ld)", (long)getpid());
    print_iflist(1);
    print_iflist(2);
}

/*
 * signal handler for SIGUSR2
 */
void sigusr2_handler(int sig)
{
    rec_log("info: SIGUSR2 called(PID: %ld)", (long)getpid());
    print_ndlist();
}

int set_rt_groups(void)
{
    int groups;

    /* set netlink groups flag to receive events */
    groups = RTMGRP_NOTIFY;
    if(msg_opts & M_LINK)
        groups |= RTMGRP_LINK;
    if(msg_opts & M_NEIGH)
        groups |= RTMGRP_NEIGH;
    if(msg_opts & M_IFADDR) {
        if(msg_opts & M_IPV4)
            groups |= RTMGRP_IPV4_IFADDR;
        if(msg_opts & M_IPV6)
            groups |= RTMGRP_IPV6_IFADDR;
        if(!(msg_opts & (M_IPV4 | M_IPV6)))
            groups |= RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    }
    if(msg_opts & M_ROUTE) {
        if(msg_opts & M_IPV4)
            groups |= RTMGRP_IPV4_ROUTE;
        if(msg_opts & M_IPV6)
            groups |= RTMGRP_IPV6_ROUTE;
        if(!(msg_opts & (M_IPV4 | M_IPV6)))
            groups |= RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
    }
    if(msg_opts & M_RULE) {
        if(msg_opts & M_IPV4)
            groups |= RTMGRP_IPV4_RULE;
        if(msg_opts & M_IPV6)
            groups |= (1 << (RTNLGRP_IPV6_RULE - 1));
        if(!(msg_opts & (M_IPV4 | M_IPV6)))
            groups |= RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_RULE;
    }
    if(msg_opts & M_TC)
        groups |= RTMGRP_TC;

    if(!(msg_opts & (M_LINK | M_NEIGH | M_IFADDR | M_ROUTE | M_RULE | M_TC))) {
        if(msg_opts & M_IPV4)
            groups |= RTMGRP_LINK | RTMGRP_NEIGH |
                RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE |
                RTMGRP_TC;
        if(msg_opts & M_IPV6)
            groups |= RTMGRP_LINK | RTMGRP_NEIGH |
                RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_RULE |
                RTMGRP_TC;
        /* receive all events if the flag is set to only L_DEBUG or none */
        if(!(msg_opts & (M_IPV4 | M_IPV6)))
            groups |= RTMGRP_LINK | RTMGRP_NEIGH | 
                RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE |
                RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_RULE |
                RTMGRP_TC;
    }

    return(groups);
}

int set_xfrm_groups(void)
{
    int groups = 0;

    /* set netlink groups flag to receive events */
    if((msg_opts & M_XFRM) || !msg_opts)
        groups |= XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE | XFRMGRP_SA |
            XFRMGRP_POLICY | XFRMGRP_AEVENTS | XFRMGRP_REPORT |
            XFRMGRP_MIGRATE | XFRMGRP_MAPPING;

    return(groups);
}
/*
 * open a rtnetlink socket
 */
int open_netlink_socket(unsigned groups, int proto)
{
    int sock, ret;
    int len = sizeof(rcv_buflen);
    struct sockaddr_nl nla;

    /* open netlink socket */
    sock = socket(AF_NETLINK, SOCK_RAW, proto);
    if(sock < 0) {
        rec_log("error: %s: socket(): %s", __func__, strerror(errno));
        exit(1);
    }

    /* initialization */
    memset(&nla, 0, sizeof(nla));

    /* set & bind local address */
    nla.nl_family = AF_NETLINK;
    nla.nl_pid = getpid();
    nla.nl_groups = groups;
    bind(sock, (struct sockaddr *)&nla, sizeof(nla));

    /* set receive buffer size */
    if(rcv_buflen) {
        ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcv_buflen, len);
        if(ret < 0) {
            rec_log("error: %s: setsockopt(): %s", __func__, strerror(errno));
            exit(1);
        }
    }

    return(sock);
}

/*
 * send a request to kernel through rtnetlink socket
 */
int send_request(int sock, int type, int family)
{
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_nl nla;
    struct {
        struct nlmsghdr nlm;
        struct rtgenmsg rtgm;
    } req;
    int err;

    /* initialization */
    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&nla, 0, sizeof(nla));
    memset(&req, 0, sizeof(req));

    /* set remote address */
    nla.nl_family = AF_NETLINK;

    /* set netlink message header */
    req.nlm.nlmsg_len = NLMSG_LENGTH(sizeof(req.rtgm));
    req.nlm.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlm.nlmsg_type = type;

    /* set routing message header */
    req.rtgm.rtgen_family = family;

    /* set message header */
    iov.iov_base = (void *)&req;
    iov.iov_len = sizeof(req);

    msg.msg_name = (void *)&nla;
    msg.msg_namelen = sizeof(nla);
    msg.msg_iov = (void *)&iov;
    msg.msg_iovlen = 1;

    /* send request message */
    err = sendmsg(sock, &msg, 0);
    if(err < 0) {
        rec_log("error: %s: sendmsg(): %s", __func__, strerror(errno));
        return(1);
    }

    return(0);
}

/*
 * receive a reply from kernel through rtnetlink socket
 */
int recv_reply(int sock, int type)
{
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_nl nla;
    char buf[16384];
    int err, len;

    /* initialization */
    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&nla, 0, sizeof(nla));
    memset(buf, 0, sizeof(buf));

    /* set message header */
    msg.msg_name = (void *)&nla;
    msg.msg_namelen = sizeof(nla);
    msg.msg_iov = (void *)&iov;
    msg.msg_iovlen = 1;

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    /* receive loop */
    while(1) {
        memset(buf, 0, sizeof(buf));
        len = recvmsg(sock, &msg, 0);
        if(len < 0) {
            if(errno == EINTR || errno == EAGAIN)
                continue;
            rec_log("error: %s: recvmsg(): %s", __func__, strerror(errno));
            return(1);
        } else if(len == 0) {
            rec_log("error: %s: recvmsg(): receive EOF", __func__);
            return(1);
        }

        /* verify whether a message originates from kernel */
        if(nla.nl_pid) {
            rec_log("error: %s: received a message from invalid sender(%d)",
                __func__, nla.nl_pid);
            continue;
        }

        if(type == RTM_GETLINK) {
            /* create interface list */
            err = create_iflist(&msg);
            if(err > 0)
                break;
            else if(err < 0)
                return(1);
        } else if(type == RTM_GETNEIGH) {
            /* create neighbor discovery list */
            err = create_ndlist(&msg);
            if(err)
                break;
            else if(err < 0)
                return(1);
        }
    }

    return(0);
}

/*
 * logging receive buffer size of socket
 */
void get_recv_buf_len(int sock) {
    int res, buflen;
    int len = sizeof(buflen);

    res = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buflen, (socklen_t *)&len);
    if(res < 0) {
        rec_log("error: %s: getsockopt(): %s", __func__, strerror(errno));
        exit(1);
    }
    rec_log("info: socket %d receive buffer size: %d byte", sock, buflen);

    return;
}

/*
 * receive notifications from kernel through rtnetlink socket
 */
int recv_events(int rt_sock, int xfrm_sock)
{
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_nl nla;
    char buf[8192];
    int epollfd, nfds, len, n, res;
    struct epoll_event ev, events[MAX_EVENTS];

    /* logging a receive buffer size */
    get_recv_buf_len(rt_sock);
    get_recv_buf_len(xfrm_sock);

    /* initialization */
    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&nla, 0, sizeof(nla));
    memset(buf, 0, sizeof(buf));

    /* set message header */
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    msg.msg_name = (void *)&nla;
    msg.msg_namelen = sizeof(nla);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* set up epoll */
    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        rec_log("error: epoll_create1()");
        exit(1);
    }

    /* added sockets */
    ev.events = EPOLLIN;
    ev.data.fd = rt_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, rt_sock, &ev) == -1) {
        rec_log("error: epoll_ctl(): sock %d", rt_sock);
        return(1);
    }

    ev.events = EPOLLIN;
    ev.data.fd = xfrm_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, xfrm_sock, &ev) == -1) {
        rec_log("error: epoll_ctl(): sock %d", xfrm_sock);
        return(1);
    }

    /* loop for receiving events */
    for(;;) {
        /* detect signal received */
        if(sigterm_received || sigint_received)
            break;

        /* wait for events */
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            rec_log("error: epoll_wait()");
            return(1);
        }

        for (n = 0; n < nfds; ++n) {
            /* clear buffer */
            memset(buf, 0, sizeof(buf));

            /* receive events */
            len = recvmsg(events[n].data.fd, &msg, 0);
            if(len < 0) {
                rec_log("error: %s: recvmsg(): %s", __func__, strerror(errno));

                if(errno == EINTR || errno == EAGAIN ||
                    errno == ENOBUFS || errno == ENOMEM)
                    continue;

                return(1);
            } else if(!len) {
                rec_log("error: %s: recvmsg(): receive EOF", __func__);
                return(1);
            }

            /* verify whether a message originates from kernel */
            if(nla.nl_pid) {
                rec_log("error: %s: received a message from invalid sender(%d)",
                    __func__, nla.nl_pid);
                continue;
            }

            /* parse messages */
            if (events[n].data.fd == rt_sock)
                res = parse_rt_events(&msg);
            else if (events[n].data.fd == xfrm_sock)
                res = parse_xfrm_events(&msg);
            if(res < 0)
                return(1);
        }
    }

    return(0);
}

/*
 * parse route events
 */
int parse_rt_events(struct msghdr *mhdr)
{
    struct nlmsghdr *nlh;
    struct nlmsgerr *nle;
    int nlh_len;

    /* get netlink message header */
    nlh = mhdr->msg_iov->iov_base;
    nlh_len = mhdr->msg_iov->iov_len;

    /* parse netlink message type */
    for( ; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
        switch(nlh->nlmsg_type) {
            /* interface link message */
            case RTM_NEWLINK:
            case RTM_DELLINK:
                parse_ifimsg(nlh);
                break;
            /* interface address message */
            case RTM_NEWADDR:
            case RTM_DELADDR:
                parse_ifamsg(nlh);
                break;
            /* neighbor discovery message */
            case RTM_NEWNEIGH:
            case RTM_DELNEIGH:
                parse_ndmsg(nlh);
                break;
            /* route message */
            case RTM_NEWROUTE:
            case RTM_DELROUTE:
                parse_rtmsg(nlh);
                break;
#ifdef HAVE_LINUX_FIB_RULES_H
            /* fib rule header */
            case RTM_NEWRULE:
            case RTM_DELRULE:
                parse_frhdr(nlh);
                break;
#endif
            /* traffic control header */
            case RTM_NEWQDISC:
            case RTM_DELQDISC:
            case RTM_NEWTCLASS:
            case RTM_DELTCLASS:
                parse_tcmsg_qdisc(nlh);
                break;
            case RTM_NEWTFILTER:
            case RTM_DELTFILTER:
                parse_tcmsg_filter(nlh);
                break;
            case RTM_NEWACTION:
            case RTM_DELACTION:
                parse_tcamsg(nlh);
                break;
            /* error message */
            case NLMSG_ERROR:
                nle = (struct nlmsgerr *)NLMSG_DATA(nlh);
                rec_log("error: %s: nlmsg error: %s",
                    __func__, strerror(nle->error));
                break;
            /* unknown message */
            default:
                rec_log("error: %s: unknown nlsmg_type: %d",
                    __func__, (int)nlh->nlmsg_type);
        }
    }

    return(0);
}

/*
 * parse xfrm events
 */
int parse_xfrm_events(struct msghdr *mhdr) {
    struct nlmsghdr *nlh;
    struct nlmsgerr *nle;
    int nlh_len;

    /* get netlink message header */
    nlh = mhdr->msg_iov->iov_base;
    nlh_len = mhdr->msg_iov->iov_len;

    /* parse netlink message type */
    for( ; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
        switch(nlh->nlmsg_type) {
            /* ipsec sa message */
            case XFRM_MSG_NEWSA:
                rec_log("info: ipsec new sa");
                break;
            case XFRM_MSG_DELSA:
                rec_log("info: ipsec del sa");
                break;
            /* ipsec policy message */
            case XFRM_MSG_NEWPOLICY:
                rec_log("info: ipsec new policy");
                break;
            case XFRM_MSG_DELPOLICY:
                rec_log("info: ipsec del policy");
                break;
        }
    }

    return(0);
}
