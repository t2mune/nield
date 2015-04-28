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
#ifndef _NIELD_
#define _NIELD_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* ANSI C header files */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>

/* not ANSI C header files */
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h> /* INET_ADDRSTRLEN, INET6_ADDRSTRLEN */
#include <sys/types.h>
#include <sys/socket.h> /* bits/socket.h, PF_*, AF_* */
#include <netdb.h>
#include <asm/types.h>
#include <net/ethernet.h> /* ETHER_ADDR_LEN */
#include <linux/types.h> /* __u8, __u16, __u32, __u64 */
#include <linux/rtnetlink.h> /* linux/if_link.h */
#include <linux/if_arp.h>
#ifdef HAVE_LINUX_FIB_RULES_H
# include <linux/fib_rules.h>
#endif
#include <linux/if.h> /* IFNAMSIZ */
#include <linux/ip.h> /* struct iphdr */
#include <linux/if_vlan.h> /* VLAN_FLAG_* */
#include <linux/if_tunnel.h> /* IFLA_GRE_* */
#include <linux/if_ether.h> /* ETH_P_* */
#include <linux/if_bridge.h>
#include <linux/if_bonding.h>
#include <linux/gen_stats.h>
#include <linux/pkt_cls.h> /* linux/pkt_sched.h */
#ifdef HAVE_LINUX_TC_ACT_TC_CSUM_H
# include <linux/tc_act/tc_csum.h>
#endif
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_ipt.h>
#include <linux/tc_act/tc_mirred.h>
#ifdef HAVE_LINUX_TC_ACT_TC_NAT_H
# include <linux/tc_act/tc_nat.h>
#endif
# include <linux/tc_act/tc_pedit.h>
#ifdef HAVE_LINUX_TC_ACT_TC_SKBEDIT_H
# include <linux/tc_act/tc_skbedit.h>
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
#include <linux/tc_ematch/tc_em_cmp.h>
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
#include <linux/tc_ematch/tc_em_meta.h>
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_NBYTE_H
#include <linux/tc_ematch/tc_em_nbyte.h>
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_TEXT_H
#include <linux/tc_ematch/tc_em_text.h>
#endif

#include "list.h"

/* default value */
#define NIELD_USAGE          "[-vh46inar] [-p lock_file] [-l log_file] [-s buffer_size] [-L syslog_facility] [-d debug_file]"
#define LOG_FILE_DEFAULT     "/var/log/nield.log"
#define DEBUG_FILE_DEFAULT   "/var/log/nield.dbg"
#define LOCK_FILE            "/var/run/nield.pid"
#define IFLIST_FILE          "/tmp/nield.iflist"
#define IFHIST_FILE          "/tmp/nield.ifhist"
#define NDLIST_FILE          "/tmp/nield.ndlist"
#define MAX_STR_SIZE         128
#define MAX_MSG_SIZE         2048
#define MODULE_NAME_LEN      (64 - sizeof(unsigned long))
#define BOND_MAX_ARP_TARGETS 32

/* logging option flag */
#define L_LOCAL   0x0001
#define L_SYSLOG  0x0002
#define L_DEBUG   0x0004

/* message option flag */
#define M_IPV4    0x0001
#define M_IPV6    0x0002
#define M_LINK    0x0004
#define M_NEIGH   0x0008
#define M_IFADDR  0x0010
#define M_ROUTE   0x0020
#define M_RULE    0x0040
#define M_TC      0x0080

/* interface message type flag */
#define IF_ADD    0x0001
#define IF_DEL    0x0002
#define IF_CHANGE 0x0004

/* interface list entry format */
struct iflist_entry {
	unsigned index;
	char name[IFNAMSIZ];
	unsigned char addr[INET6_ADDRSTRLEN+1];
	unsigned char brd[INET6_ADDRSTRLEN+1];
	unsigned short type;
	unsigned flags;
	unsigned short vid;
	int mtu;
	char kind[MODULE_NAME_LEN];
	int index_master;
	char name_master[IFNAMSIZ];
	unsigned char br_attached;
	unsigned char br_state;
	struct list_head list;
};

/* neighbor discovery cache format */
struct ndlist_entry {
	unsigned ifindex;
	char ifname[IFNAMSIZ];
	char ipaddr[INET6_ADDRSTRLEN+1];
	char lladdr[INET6_ADDRSTRLEN+1];
	struct list_head list;
};

/* defined in net/if.h but that conflicts with linux/if.h... */
extern unsigned int if_nametoindex (const char *__ifname);
extern char *if_indextoname (unsigned int __ifindex, char *__ifname);

/* nield.c */
void close_exit(int sock, int log_flag, int ret);
int set_options(int argc, char *argv[]);
int get_log_opts(void);
int get_msg_opts(void);
int set_facility(char *facility_name);
int get_facility(void);
int open_lock(void);
int write_lock(void);
void close_lock(void);
int init_daemon(void);
int set_signal_handlers(void);
void sigterm_handler(int sig);
void sigint_handler(int sig);
void sigusr1_handler(int sig);
void sigusr2_handler(int sig);
int set_rtnetlink_groups(void);
int open_netlink_socket(unsigned groups);
int send_request(int sock, int type, int family);
int recv_reply(int sock, int type);
int recv_events(int sock);
int parse_events(struct msghdr *mhdr);

/* log.c */
int open_log(char *filename);
char *add_log(char *msg, char *mp, char *format, ...);
void rec_log(char *format, ...);
void close_log(void);

/* debug.c */
int open_dbg(char *filename);
void rec_dbg(int lev, char *format, ...);
void close_dbg(void);

/* nlmsg.c */
void debug_nlmsg(int lev, struct nlmsghdr *nlh);
const char *debug_n2s_nlmsg_type(int type);

/* rta.c */
int debug_rta_len_chk(int lev, struct rtattr *rta, const char *name, size_t len);
void debug_rta_ignore(int lev, struct rtattr *rta, const char *name);
void debug_rta_none(int lev, struct rtattr *rta, const char *name);
void debug_rta_u8(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned char num, unsigned char debug));
void debug_rta_u8x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned char num, unsigned char debug));
void debug_rta_u16(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug));
void debug_rta_u16x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug));
void debug_rta_n16(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug));
void debug_rta_n16x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug));
void debug_rta_u32(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned num, unsigned char debug));
void debug_rta_u32x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned num, unsigned char debug));
void debug_rta_s32(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(int num, unsigned char debug));
void debug_rta_s32x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(int num, unsigned char debug));
void debug_rta_str(int lev, struct rtattr *rta, const char *name, char *str, unsigned len);
void debug_rta_ifindex(int lev, struct rtattr *rta, const char *name);
void debug_rta_arphrd(int lev, struct rtattr *rta, const char *name, unsigned short type);
int arphrd_ntop(unsigned short type, struct rtattr *ifla, char *addr, int addrlen);
void debug_rta_af(int lev, struct rtattr *rta, const char *name, unsigned short family);
int inet_ntop_ifa(int family, struct rtattr *ifa, char *saddr, int slen);
void debug_rta_tc_addr(int lev, struct tcmsg *tcm, struct rtattr *rta, const char *name);
int inet_ntop_tc_addr(struct tcmsg *tcm, struct rtattr *tca, char *addrstr, int addrstrlen);
void debug_tca_classid(int lev, struct rtattr *tca, const char *name);
void parse_tc_handle(char *p, int len, unsigned id);

/* ifimsg.c */
int create_iflist(struct msghdr *msg);
char *if_indextoname_from_lists(int index, char *name);
char *if_indextoname_from_iflist(int index, char *name);
char *if_indextoname_from_ifhist(int index, char *name);
unsigned short get_type_from_iflist(int index);
unsigned short get_type_from_ifhist(int index);
void print_iflist(int num);
int parse_ifimsg(struct nlmsghdr *nlh);
void parse_rtm_newlink(char *msg, struct iflist_entry *ifle, struct iflist_entry *ifle_tmp,
	struct rtattr *ifla[]);
void parse_rtm_dellink(char *msg, struct iflist_entry *ifle, struct iflist_entry *ifle_tmp);
int parse_ifla_ifname(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_link(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_address(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_broadcast(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_mtu(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
#if HAVE_DECL_IFLA_LINKINFO
int parse_ifla_linkinfo(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_info_kind(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle);
int parse_ifla_info_data(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle);
#endif
int parse_ifla_master(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_protinfo(struct rtattr *ifla, struct iflist_entry *ifle, unsigned char family);
void debug_ifimsg(int lev, struct ifinfomsg *ifim, struct rtattr *ifla[], int ifim_len);
void debug_ifla_stats(int lev, struct rtattr *ifla, const char *name);
void debug_ifla_protinfo(int lev, struct rtattr *ifla, const char *name, unsigned char family);
void debug_ifla_map(int lev, struct rtattr *ifla, const char *name);
#if HAVE_DECL_IFLA_LINKINFO
void debug_ifla_linkinfo(int lev, struct rtattr *ifla, const char *name, struct ifinfomsg *ifim);
void debug_ifla_info_data(int lev, struct rtattr *info, const char *name,
    struct ifinfomsg *ifim, char *kind, int len);
#endif
#if HAVE_DECL_IFLA_INFO_SLAVE_KIND
void debug_ifla_info_slave_data(int lev, struct rtattr *info,
    const char *name, struct ifinfomsg *ifim, char *kind, int len);
#endif
#if HAVE_DECL_IFLA_STATS64
void debug_ifla_stats64(int lev, struct rtattr *ifla, const char *name);
#endif
const char *conv_af_type(unsigned char family, unsigned char debug);
const char *conv_arphrd_type(unsigned short type, unsigned char debug);
const char *conv_iff_flags(unsigned flags, unsigned char debug);
const char *conv_if_oper_state(unsigned char state, unsigned char debug);
const char *conv_if_link_mode(unsigned char mode, unsigned char debug);

/* ifimsg_brport.c */
#if HAVE_DECL_IFLA_BRPORT_UNSPEC
void parse_rtm_newlink_bridge(struct iflist_entry *ifle, struct iflist_entry *ifle_tmp, struct rtattr *ifla[]);
void parse_rtm_dellink_bridge(struct iflist_entry *ifle);
int parse_ifla_brport(struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_brport_state(struct rtattr *brp, struct iflist_entry *ifle);
void debug_ifla_brport(int lev, struct rtattr *ifla);
const char *conv_br_state(unsigned char state, unsigned char debug);
#endif

/* ifimsg_gre.c */
#if HAVE_DECL_IFLA_GRE_UNSPEC
int parse_ifla_gre(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle);
int parse_ifla_gre_local(char *msg, char **mp, struct rtattr *greinfo, struct iflist_entry *ifle);
int parse_ifla_gre_remote(char *msg, char **mp, struct rtattr *greinfo, struct iflist_entry *ifle);
void debug_ifla_gre(int lev, struct ifinfomsg *ifim, struct rtattr *info);
const char *conv_gre_flags(unsigned short flags, unsigned char debug);
#endif

/* ifimsg_vlan.c */
#if HAVE_DECL_IFLA_VLAN_UNSPEC
int parse_ifla_vlan(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle);
int parse_ifla_vlan_id(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle);
int parse_ifla_vlan_egress_qos(char *msg, char **mp, struct rtattr *vlan, struct iflist_entry *ifle);
int parse_ifla_vlan_ingress_qos(char *msg, char **mp, struct rtattr *vlan, struct iflist_entry *ifle);
int parse_vlan_qos_mapping(char *msg, char **mp, struct rtattr *qos, struct iflist_entry *ifle);
int parse_ifla_vlan_protocol(char *msg, char **mp, struct rtattr *vlan, struct iflist_entry *ifle);
void debug_ifla_vlan(int lev, struct rtattr *info);
void debug_ifla_vlan_flags(int lev, struct rtattr *vlan, const char *name);
void debug_ifla_vlan_qos(int lev, struct rtattr *vlan, const char *name);
const char *conv_vlan_flags(int flags, unsigned char debug);
#endif

/* ifimsg_macvlan.c */
#if HAVE_DECL_IFLA_MACVLAN_UNSPEC
int parse_ifla_macvlan(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle);
int parse_ifla_macvlan_mode(char *msg, char **mp, struct rtattr *macvlan,
    struct iflist_entry *ifle);
void debug_ifla_macvlan(int lev, struct rtattr *info);
const char *conv_macvlan_mode(unsigned mode, unsigned char debug);
#endif

/* ifimsg_vxlan.c */
#if HAVE_DECL_IFLA_VXLAN_UNSPEC
int parse_ifla_vxlan(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle);
int parse_ifla_vxlan_link(char *msg, char **mp, struct rtattr *vxlan, struct iflist_entry *ifle);
int parse_ifla_vxlan_local(char *msg, char **mp, struct rtattr *vxlan, struct iflist_entry *ifle, unsigned short family);
int parse_ifla_vxlan_port_range(char *msg, char **mp, struct rtattr *vxlan, struct iflist_entry *ifle);
int parse_ifla_vxlan_group(char *msg, char **mp, struct rtattr *vxlan, struct iflist_entry *ifle, unsigned short family);
#if HAVE_DECL_IFLA_VXLAN_PORT
int parse_ifla_vxlan_port(char *msg, char **mp, struct rtattr *vxlan, struct iflist_entry *ifle);
#endif
void debug_ifla_vxlan(int lev, struct rtattr *info);
void debug_ifla_vxlan_port_range(int lev, struct rtattr *vxlan, const char *name);
#endif

/* ifimsg_bond.c */
#if HAVE_DECL_IFLA_BOND_UNSPEC
int parse_ifla_bond(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle);
int parse_ifla_bond_mode(char *msg, char **mp, struct rtattr *bond, struct iflist_entry *ifle);
#if HAVE_DECL_IFLA_BOND_MIIMON
int parse_ifla_bond_xmit_hash_policy(char *msg, char **mp, struct rtattr *bond, struct iflist_entry *ifle);
#endif
void debug_ifla_bond(int lev, struct rtattr *info);
#if HAVE_DECL_IFLA_BOND_MIIMON
void debug_ifla_bond_arp_ip_target(int lev, struct rtattr *bond, const char *name);
void debug_ifla_bond_ad_info(int lev, struct rtattr *bond, const char *name);
void debug_ifla_bond_slave(int lev, struct rtattr *bond);
#endif
const char *conv_bond_mode(unsigned char mode, unsigned char debug);
#if HAVE_DECL_IFLA_BOND_MIIMON
const char *conv_bond_xmit_policy(unsigned char policy, unsigned char debug);
const char *conv_bond_state(unsigned char state, unsigned char debug);
const char *conv_bond_link(unsigned char state, unsigned char debug);
#endif
#endif

/* ifamsg.c */
int parse_ifamsg(struct nlmsghdr *nlh);
void debug_ifamsg(int lev, struct ifaddrmsg *ifam, struct rtattr *ifa[], int ifam_len);
void debug_ifa_cacheinfo(int lev, struct rtattr *ifa, const char *name);
void conv_ifa_flags(int flags, char *flags_list, int len);
const char *conv_ifa_scope(int scope, unsigned char debug);

/* ndmsg.c */
int create_ndlist(struct msghdr *msg);
void print_ndlist(void);
int parse_ndmsg(struct nlmsghdr *nlh);
int parse_rtm_newneigh(char *ndm_type, struct ndmsg *ndm, struct ndlist_entry *ndle_tmp);
int parse_rtm_delneigh(char *ndm_type, struct ndmsg *ndm, struct ndlist_entry *ndle_tmp);
void debug_ndmsg(int lev, struct ndmsg *ndm, struct rtattr *nda[], int ndm_len);
void debug_nda_cacheinfo(int lev, struct rtattr *nda, const char *name);
const char *conv_nud_state(int state, unsigned char debug);
const char *conv_ntf_flags(int flags, unsigned char debug);

/* rtmsg.c */
int parse_rtmsg(struct nlmsghdr *nlh);
void debug_rtmsg(int lev, struct rtmsg *rtm, struct rtattr *rta[], int rtm_len);
void debug_rta_metrics(int lev, struct rtattr *rta, const char *name);
void debug_rta_multipath(int lev, struct rtmsg *rtm, struct rtattr *rta, const char *name);
void debug_rta_cacheinfo(int lev, struct rtattr *rta, const char *name);
const char *conv_rt_table(int table, unsigned char debug);
const char *conv_rtprot(int protocol, unsigned char debug);
const char *conv_rt_scope(int scope);
const char *conv_rtn_type(int type, unsigned char debug);
void conv_rtm_flags(int flags, char *flags_list, int len);
void conv_rtnh_flags(int flags, char *flags_list, int len);

/* frhdr.c */
#ifdef HAVE_LINUX_FIB_RULES_H
int parse_frhdr(struct nlmsghdr *nlh);
void debug_frhdr(int lev, struct fib_rule_hdr *frh, struct rtattr *fra[], int frh_len);
const char *conv_fr_act(int action, unsigned char debug);
void conv_fib_rule_flags(int flags, char *flags_list, int len);
#endif

/* tcmsg_qdisc.c */
int parse_tcmsg_qdisc(struct nlmsghdr *nlh);
void conv_unit_rate(char *str, int len, double num);
void conv_unit_size(char *str, int len, double num);
void conv_unit_usec(char *str, int len, double usec);
int get_us2tick(void);
double get_burst_size(unsigned rate, unsigned buffer);
double get_latency(unsigned rate, unsigned buffer, unsigned limit);
void debug_tcmsg(int lev, struct nlmsghdr *nlh, struct tcmsg *tcm, struct rtattr *tca[], int tcm_len);
void debug_tca_options(int lev, struct tcmsg *tcm, struct rtattr *tca, const char *name, char *kind, int len);
void debug_tca_stats(int lev, struct rtattr *tca, const char *name);
void debug_tca_xstats(int lev, struct rtattr *tca, const char *name, char *kind, int len);
void debug_tca_rate(int lev, struct rtattr *tca, const char *name);
void debug_tca_stats2(int lev, struct rtattr *tca, const char *name);
void debug_tca_stats2_attr(int lev, struct rtattr *tca);
void debug_tca_stats_basic(int lev, struct rtattr *stats2, const char *name);
void debug_tca_stats_rate_est(int lev, struct rtattr *stats2, const char *name);
void debug_tca_stats_queue(int lev, struct rtattr *stats2, const char *name);
void debug_tca_stats_app(int lev, struct rtattr *stats2, const char *name);
#if HAVE_DECL_TCA_STAB_UNSPEC
void debug_tca_stab(int lev, struct rtattr *tca, const char *name);
void debug_tca_stab_base(int lev, struct rtattr *stab, const char *name);
#endif
void debug_tc_ratespec(int lev, struct tc_ratespec *rate, char *name);

/* tcmsg_qdisc_prio.c */
int parse_tca_options_prio(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_prio(int lev, struct rtattr *tca, const char *name);

/* tcmsg_qdisc_fifo.c */
int parse_tca_options_pfifo(char *msg, char **mp, struct rtattr *tca);
int parse_tca_options_bfifo(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_fifo(int lev, struct rtattr *tca, const char *name);

/* tcmsg_qdisc_multiq.c */
#ifdef HAVE_STRUCT_TC_MULTIQ_QOPT_BANDS
int parse_tca_options_multiq(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_multiq(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_qdisc_plug.c */
#ifdef HAVE_STRUCT_TC_PLUG_QOPT_ACTION
int parse_tca_options_plug(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_plug(int lev, struct rtattr *tca, const char *name);
const char *conv_tcq_plug_action(int action);
#endif

/* tcmsg_qdisc_tbf.c */
int parse_tca_options_tbf(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_tbf(int lev, struct rtattr *tca, const char *name);
void debug_tca_tbf_parms(int lev, struct rtattr *tbf, const char *name);

/* tcmsg_qdisc_sfq.c */
int parse_tca_options_sfq(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_sfq(int lev, struct rtattr *tca, const char *name);
#ifdef HAVE_STRUCT_TC_SFQ_XSTATS_ALLOT
void debug_tc_sfq_xstats(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_qdisc_red.c */
int parse_tca_options_red(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_red(int lev, struct rtattr *tca, const char *name);
void debug_tca_red_parms(int lev, struct rtattr *red, const char *name);
void debug_tc_red_xstats(int lev, struct rtattr *tca, const char *name);
void conv_tc_red_flags(int flags, char *flags_list, int len, unsigned char debug);

/* tcmsg_qdisc_gred.c */
int parse_tca_options_gred(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_gred(int lev, struct rtattr *tca, const char *name);
void debug_tca_gred_parms(int lev, struct rtattr *gred, const char *name);
void debug_tca_gred_dps(int lev, struct rtattr *gred, const char *name);
#if HAVE_DECL_TCA_GRED_MAX_P
void debug_tca_gred_max_p(int lev, struct rtattr *gred, const char *name);
#endif

/* tcmsg_qdisc_choke.c */
#if HAVE_DECL_TCA_CHOKE_UNSPEC
int parse_tca_options_choke(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_choke(int lev, struct rtattr *tca, const char *name);
void debug_tca_choke_parms(int lev, struct rtattr *choke, const char *name);
void debug_tc_choke_xstats(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_qdisc_htb.c */
int parse_tca_options_htb(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_htb(int lev, struct rtattr *tca, const char *name);
void debug_tca_htb_parms(int lev, struct rtattr *htb, const char *name);
void debug_tca_htb_init(int lev, struct rtattr *htb, const char *name);
void debug_tc_htb_xstats(int lev, struct rtattr *tca, const char *name);

/* tcmsg_qdisc_hfsc.c */
int parse_tca_options_hfsc(char *msg, char **mp, struct rtattr *tca);
int print_hfsc_sc(char *msg, char **mp, char *name, struct tc_service_curve *sc);
void debug_tca_options_hfsc(int lev, struct rtattr *tca, const char *name);
void debug_tca_hfsc_sc(int lev, struct rtattr *hfsc, const char *name);

/* tcmsg_qdisc_cbq.c */
int parse_tca_options_cbq(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_cbq(int lev, struct rtattr *tca, const char *name);
void debug_tca_cbq_lssopt(int lev, struct rtattr *cbq, const char *name);
void debug_tca_cbq_wrropt(int lev, struct rtattr *cbq, const char *name);
void debug_tca_cbq_fopt(int lev, struct rtattr *cbq, const char *name);
void debug_tca_cbq_ovl_strategy(int lev, struct rtattr *cbq, const char *name);
void debug_tca_cbq_rate(int lev, struct rtattr *cbq, const char *name);
void debug_tca_cbq_police(int lev, struct rtattr *cbq, const char *name);
void debug_tc_cbq_xstats(int lev, struct rtattr *tca, const char *name);
void conv_tcf_cbq_lss_change(int change, char *change_list, int len);
void conv_tcf_cbq_lss_flags(int flags, char *flags_list, int len);
void conv_tc_cbq_ovl_strategy(int strategy, char *strategy_list, int len);

/* tcmsg_qdisc_dsmark.c */
int parse_tca_options_dsmark(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_dsmark(int lev, struct rtattr *tca, const char *name);

/* tcmsg_qdisc_netem.c */
int parse_tca_options_netem(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_netem(int lev, struct rtattr *tca, const char *name);
void debug_tca_netem_corr(int lev, struct rtattr *netem, const char *name);
void debug_tca_netem_reorder(int lev, struct rtattr *netem, const char *name);
void debug_tca_netem_corrupt(int lev, struct rtattr *netem, const char *name);
#if HAVE_DECL_TCA_NETEM_LOSS
void debug_tca_netem_loss(int lev, struct rtattr *netem, const char *name);
void debug_netem_loss_gi(int lev, struct rtattr *loss, const char *name);
void debug_netem_loss_ge(int lev, struct rtattr *loss, const char *name);
#endif
#if HAVE_DECL_TCA_NETEM_RATE
void debug_tca_netem_rate(int lev, struct rtattr *netem, const char *name);
#endif

/* tcmsg_qdisc_drr.c */
#if HAVE_DECL_TCA_DRR_UNSPEC
int parse_tca_options_drr(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_drr(int lev, struct rtattr *tca, const char *name);
void debug_tc_drr_xstats(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_qdisc_sfb.c */
#if HAVE_DECL_TCA_SFB_UNSPEC
int parse_tca_options_sfb(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_sfb(int lev, struct rtattr *tca, const char *name);
void debug_tca_sfb_parms(int lev, struct rtattr *sfb, const char *name);
void debug_tc_sfb_xstats(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_qdisc_qfq.c */
#if HAVE_DECL_TCA_QFQ_UNSPEC
int parse_tca_options_qfq(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_qfq(int lev, struct rtattr *tca, const char *name);
void debug_tc_qfq_xstats(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_qdisc_codel.c */
#if HAVE_DECL_TCA_CODEL_UNSPEC
int parse_tca_options_codel(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_codel(int lev, struct rtattr *tca, const char *name);
void debug_tc_codel_xstats(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_qdisc_fq_codel.c */
#if HAVE_DECL_TCA_FQ_CODEL_UNSPEC
int parse_tca_options_fq_codel(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_fq_codel(int lev, struct rtattr *tca, const char *name);
void debug_tc_fq_codel_xstats(int lev, struct rtattr *tca, const char *name);
#endif

/* tcmsg_filter.c */
int parse_tcmsg_filter(struct nlmsghdr *nlh);
int parse_tca_classid(char *msg, char **mp, struct rtattr *tca);
int parse_tca_indev(char *msg, char **mp, struct rtattr *tca);
int parse_tca_mask(char *msg, char **mp, struct rtattr *tca);
void parse_u32_handle(char *p, int len, unsigned handle);
int parse_tca_ematch(char *msg, char *mp, struct rtattr *tca);
int parse_tca_ematch_tree_hdr(struct rtattr *em_tree, int *num);
int parse_tca_ematch_tree_list(char *msg, char *mp, struct rtattr *em_tree, int num);
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
int parse_ematch_cmp(char *msg, char *mp, void *p, int len);
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_NBYTE_H
int parse_ematch_nbyte(char *msg, char *mp, void *p, int len);
#endif
int parse_ematch_u32(char *msg, char *mp, void *p, int len);
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
int parse_ematch_meta(char *msg, char *mp, void *p, int len);
int parse_tca_em_meta_value(char *msg, char **mp, struct tcf_meta_val *val, struct rtattr *meta);
#endif
void debug_tca_ematch(int lev, struct rtattr *tca, const char *name);
int debug_tca_ematch_tree_hdr(int lev, struct rtattr *ematch, const char *name);
void debug_tca_ematch_tree_list(int lev, struct rtattr *em_tree, const char *name, int num);
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
void debug_ematch_cmp(int lev, void *p, int len);
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_NBYTE_H
void debug_ematch_nbyte(int lev, void *p, int len);
#endif
void debug_ematch_u32(int lev, void *p, int len);
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
void debug_ematch_meta(int lev, void *p, int len);
struct tcf_meta_hdr *debug_tca_em_meta_hdr(int lev, struct rtattr *meta, const char *name);
void debug_tca_em_meta_value(int lev, struct rtattr *meta, const char *name, struct tcf_meta_val *p);
#endif
void conv_tc_u32_flags(int flags, char *flags_list, int len, unsigned char debug);
const char *conv_eth_p(unsigned short proto, unsigned char debug);
const char *conv_tcf_em_kind(int kind, unsigned char debug);
const char *conv_tcf_em_flag(int flag, unsigned char debug);
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
const char *conv_tcf_em_align(int align, unsigned char debug);
#endif
const char *conv_tcf_em_opnd(int opnd, unsigned char debug);
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
const char *conv_tcf_meta_type(int type, unsigned char debug);
const char *conv_tcf_meta_id(int id, unsigned char debug);
#endif

/* tcmsg_filter_u32.c */
int parse_tca_options_u32(char *msg, char **mp, struct rtattr *tca);
int parse_tca_u32_hash(char *msg, char **mp, struct rtattr *u32);
int parse_tca_u32_link(char *msg, char **mp, struct rtattr *u32);
int parse_tca_u32_divisor(char *msg, char **mp, struct rtattr *u32);
int parse_tca_u32_mark(char *msg, char **mp, struct rtattr *u32);
int parse_tca_u32_sel(char *msg, char *mp, struct rtattr *u32);
void debug_tca_options_u32(int lev, struct rtattr *tca, const char *name);
void debug_tca_u32_link(int lev, struct rtattr *u32, const char *name);
void debug_tca_u32_sel(int lev, struct rtattr *u32, const char *name);
void debug_tca_u32_pcnt(int lev, struct rtattr *u32[], const char *name);
void debug_tca_u32_mark(int lev, struct rtattr *u32, const char *name);
const char *conv_tca_u32_hash(unsigned num, unsigned char debug);

/* tcmsg_filter_rsvp.c */
int parse_tca_options_rsvp(char *msg, char **mp, struct tcmsg *tcm, struct rtattr *tca);
int parse_tca_rsvp_dst(char *msg, char **mp, struct tcmsg *tcm, struct rtattr *rsvp);
int parse_tca_rsvp_src(char *msg, char **mp, struct tcmsg *tcm, struct rtattr *rsvp);
int parse_tca_rsvp_pinfo(char *msg, char **mp, struct rtattr *rsvp);
void debug_tca_options_rsvp(int lev, struct tcmsg *tcm, struct rtattr *tca, const char *name);
void debug_tca_rsvp_pinfo(int lev, struct rtattr *rsvp, const char *name);

/* tcmsg_filter_route.c */
int parse_tca_options_route(char *msg, char **mp, struct rtattr *tca);
int parse_tca_route4_from(char *msg, char **mp, struct rtattr *route);
int parse_tca_route4_to(char *msg, char **mp, struct rtattr *route);
int parse_tca_route4_iif(char *msg, char **mp, struct rtattr *route);
void debug_tca_options_route(int lev, struct rtattr *tca, const char *name);

/* tcmsg_filter_fw.c */
int parse_tca_options_fw(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_fw(int lev, struct rtattr *tca, const char *name);

/* tcmsg_filter_tcindex.c */
int parse_tca_options_tcindex(char *msg, char **mp, struct rtattr *tca);
int parse_tca_tcindex_hash(char *msg, char **mp, struct rtattr *tcindex);
int parse_tca_tcindex_mask(char *msg, char **mp, struct rtattr *tcindex);
int parse_tca_tcindex_shift(char *msg, char **mp, struct rtattr *tcindex);
int parse_tca_tcindex_fall_through(char *msg, char **mp, struct rtattr *tcindex);
void debug_tca_options_tcindex(int lev, struct rtattr *tca, const char *name);

/* tcmsg_filter_flow.c */
#if HAVE_DECL_TCA_FLOW_UNSPEC
int parse_tca_options_flow(char *msg, char **mp, struct rtattr *tca);
int parse_tca_flow_keys(char *msg, char **mp, struct rtattr *flow);
int parse_tca_flow_mode(char *msg, char **mp, struct rtattr *flow);
int parse_tca_flow_xor(char *msg, char **mp, struct rtattr *flow);
int parse_tca_flow_rshift(char *msg, char **mp, struct rtattr *flow);
int parse_tca_flow_addend(char *msg, char **mp, struct rtattr *flow);
int parse_tca_flow_divisor(char *msg, char **mp, struct rtattr *flow);
int parse_tca_flow_perturb(char *msg, char **mp, struct rtattr *flow);
void debug_tca_options_flow(int lev, struct rtattr *tca, const char *name);
const char *conv_flow_key(unsigned flags, unsigned char debug);
const char *conv_flow_mode(unsigned mode, unsigned char debug);
#endif

/* tcmsg_filter_basic.c */
int parse_tca_options_basic(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_basic(int lev, struct rtattr *tca, const char *name);

/* tcmsg_filter_cgroup.c */
#if HAVE_DECL_TCA_CGROUP_UNSPEC
int parse_tca_options_cgroup(char *msg, char **mp, struct rtattr *tca);
void debug_tca_options_cgroup(int lev, struct rtattr *tca, const char *name);
#endif

/* tcamsg.c */
int parse_tcamsg(struct nlmsghdr *nlh);
int parse_tca_acts(char *msg, char *mp, struct rtattr *tcaa);
int parse_tca_act(char *msg, char *mp, struct rtattr *acts);
void debug_tcamsg(int lev, struct tcamsg *tcam, struct rtattr *tcaa[], int tcam_len);
void debug_tca_acts(int lev, struct rtattr *tcaa, const char *name);
void debug_tca_act(int lev, struct rtattr *acts);
void debug_tca_act_options(int lev, struct rtattr *act, const char *name, char *kind, int len);
void debug_tca_act_stats(int lev, struct rtattr *act, const char *name);
void debug_tcf_t(int lev, struct tcf_t *tm);
const char *conv_tc_action(int action, unsigned char debug);

/* tcamsg_police.c */
int parse_tca_act_options_police(char *msg, char *mp, struct rtattr *act);
void debug_tca_act_options_police(int lev, struct rtattr *act, const char *name);
void debug_tca_police_tbf(int lev, struct rtattr *police, const char *name);
const char *conv_tc_police_action(unsigned action, unsigned char debug);

/* tcamsg_gact.c */
int parse_tca_act_options_gact(char *msg, char *mp, struct rtattr *act);
void debug_tca_act_options_gact(int lev, struct rtattr *act);
void debug_tca_gact_tm(int lev, struct rtattr *gact, const char *name);
void debug_tca_gact_parms(int lev, struct rtattr *gact, const char *name);
void debug_tca_gact_prob(int lev, struct rtattr *gact, const char *name);
const char *conv_pgact(int pgact, unsigned char debug);

/* tcamsg_pedit.c */
int parse_tca_act_options_pedit(char *msg, char *mp, struct rtattr *act);
void debug_tca_act_options_pedit(int lev, struct rtattr *act);
void debug_tca_pedit_tm(int lev, struct rtattr *pedit, const char *name);
void debug_tca_pedit_parms(int lev, struct rtattr *pedit, const char *name);

/* tcamsg_mirred.c */
int parse_tca_act_options_mirred(char *msg, char *mp, struct rtattr *act);
void debug_tca_act_options_mirred(int lev, struct rtattr *act);
void debug_tca_mirred_tm(int lev, struct rtattr *mirred, const char *name);
void debug_tca_mirred_parms(int lev, struct rtattr *mirred, const char *name);
const char *conv_tca_mirred_action(int action, unsigned char debug);

/* tcamsg_nat.c */
#ifdef HAVE_LINUX_TC_ACT_TC_NAT_H
int parse_tca_act_options_nat(char *msg, char *mp, struct rtattr *act);
void debug_tca_act_options_nat(int lev, struct rtattr *act);
void debug_tca_nat_parms(int lev, struct rtattr *nat, const char *name);
void debug_tca_nat_tm(int lev, struct rtattr *nat, const char *name);
#endif

/* tcamsg_skbedit.c */
#ifdef HAVE_LINUX_TC_ACT_TC_SKBEDIT_H
int parse_tca_act_options_skbedit(char *msg, char *mp, struct rtattr *act);
void debug_tca_act_options_skbedit(int lev, struct rtattr *act);
void debug_tca_skbedit_tm(int lev, struct rtattr *skb, const char *name);
void debug_tca_skbedit_parms(int lev, struct rtattr *skb, const char *name);
#endif

/* tcamsg_csum.c */
#ifdef HAVE_LINUX_TC_ACT_TC_CSUM_H
int parse_tca_act_options_csum(char *msg, char *mp, struct rtattr *act);
void debug_tca_act_options_csum(int lev, struct rtattr *act);
void debug_tca_csum_tm(int lev, struct rtattr *csum, const char *name);
void debug_tca_csum_parms(int lev, struct rtattr *csum, const char *name);
void conv_tca_csum_update_flags(int flags, char *flags_list, int len, unsigned char debug);
#endif
#endif /* _NIELD_ */
