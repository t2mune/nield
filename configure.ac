#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT(nield, 0.7.0a1, [t2mune@gmail.com])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign])

case "$target" in
	*linux*)
		AC_MSG_RESULT(linux)
		arch=linux
		;;
	*)
		AC_MSG_RESULT(unknown)
		AC_MSG_ERROR([$target is not supported.])
		;;
esac

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

AC_PREFIX_DEFAULT([/usr])

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([asm/types.h])
AC_CHECK_HEADERS([net/ethernet.h])
AC_CHECK_HEADERS([linux/types.h])
AC_CHECK_HEADERS(
[linux/rtnetlink.h \
linux/if_arp.h \
linux/fib_rules.h \
linux/if.h], [], [],
[[#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif]])
AC_CHECK_HEADERS([linux/ip.h])
AC_CHECK_HEADERS([linux/if_vlan.h])
AC_CHECK_HEADERS([linux/if_tunnel.h], [], [],
[[#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_LINUX_IF_H
# include <linux/if.h>
#endif
#ifdef HAVE_LINUX_IP_H
# include <linux/ip.h>
#endif]])
AC_CHECK_HEADERS([linux/if_ether.h])
AC_CHECK_HEADERS(
[linux/if_bridge.h \
linux/if_bonding], [], [],
[[#ifdef HAVE_LINUX_TYPES_H
# include <linux/types.h>
#endif]])
AC_CHECK_HEADERS([linux/gen_stats.h])
AC_CHECK_HEADERS(
[linux/pkt_cls.h \
linux/tc_act/tc_csum.h \
linux/tc_act/tc_gact.h \
linux/tc_act/tc_ipt.h \
linux/tc_act/tc_mirred.h \
linux/tc_act/tc_nat.h \
linux/tc_act/tc_pedit.h \
linux/tc_act/tc_skbedit.h], [], [],
[[#ifdef HAVE_LINUX_TYPES_H
# include <linux/types.h>
#endif]])
AC_CHECK_HEADERS([linux/tc_ematch/tc_em_cmp.h])
AC_CHECK_HEADERS([linux/tc_ematch/tc_em_meta.h])
AC_CHECK_HEADERS([linux/tc_ematch/tc_em_nbyte.h])
AC_CHECK_HEADERS([linux/tc_ematch/tc_em_text.h])
AC_CHECK_HEADERS([sys/syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T

AC_CHECK_DECLS(
[IFLA_LINKINFO,
IFLA_NET_NS_PID,
IFLA_IFALIAS,
IFLA_NUM_VF,
IFLA_VFINFO_LIST,
IFLA_STATS64,
IFLA_VF_PORTS,
IFLA_PORT_SELF,
IFLA_AF_SPEC,
IFLA_GROUP,
IFLA_NET_NS_FD,
IFLA_EXT_MASK,
IFLA_PROMISCUITY,
IFLA_NUM_TX_QUEUES,
IFLA_NUM_RX_QUEUES,
IFLA_CARRIER,
IFLA_PHYS_PORT_ID,
IFLA_BRPORT_UNSPEC,
IFLA_BRPORT_LEARNING,
IFLA_INFO_SLAVE_KIND,
IFLA_VLAN_UNSPEC,
IFLA_VLAN_PROTOCOL,
IFLA_MACVLAN_UNSPEC,
IFLA_MACVLAN_FLAGS,
MACVLAN_MODE_PASSTHRU,
IFLA_VXLAN_UNSPEC,
IFLA_VXLAN_REMOTE,
IFLA_VXLAN_GROUP,
IFLA_VXLAN_PROXY,
IFLA_VXLAN_PORT,
IFLA_VXLAN_GROUP6,
IFLA_BOND_UNSPEC,
IFLA_BOND_MIIMON,
RTA_MARK,
RT_TABLE_COMPAT,
RTPROT_DHCP], [], [],
[[#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_LINUX_RTNETLINK_H
# include <linux/rtnetlink.h>
#endif]])
AC_CHECK_DECLS(
[VLAN_FLAG_REORDER_HDR,
VLAN_FLAG_GVRP,
VLAN_FLAG_LOOSE_BINDING], [], [],
[[#ifdef HAVE_LINUX_IF_VLAN_H
# include <linux/if_vlan.h>
#endif]])
AC_CHECK_DECLS(
[IFLA_GRE_UNSPEC,
IFLA_GRE_ENCAP_LIMIT], [], [],
[[#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_LINUX_IF_H
# include <linux/if.h>
#endif
#ifdef HAVE_LINUX_IP_H
# include <linux/ip.h>
#endif
#ifdef HAVE_LINUX_IF_TUNNEL_H
# include <linux/if_tunnel.h>
#endif]])
AC_CHECK_DECLS(
[FRA_GOTO,
FRA_OIFNAME,
FR_ACT_GOTO,
FR_ACT_NOP,
FR_ACT_RES1,
FR_ACT_RES2], [], [],
[[#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_LINUX_FIB_RULES_H
# include <linux/fib_rules.h>
#endif]])
AC_CHECK_DECLS(
[TCA_RED_MAX_P,
TCA_GRED_MAX_P,
TCA_CHOKE_UNSPEC,
TCA_CHOKE_MAX_P,
TCA_NETEM_LOSS,
TCA_NETEM_RATE,
TCA_NETEM_ECN,
TCA_DRR_UNSPEC,
TCA_SFB_UNSPEC,
TCA_QFQ_UNSPEC,
TCA_CODEL_UNSPEC,
TCA_FQ_CODEL_UNSPEC,
TCA_STAB_UNSPEC,
TCA_FLOW_UNSPEC,
FLOW_KEY_RXHASH,
TCA_FW_MASK,
TCA_CGROUP_UNSPEC,
TCF_EM_VLAN,
TCF_EM_CANID,
TCF_EM_IPSET], [], [],
[[#ifdef HAVE_LINUX_TYPES_H
# include <linux/types.h>
#endif
#ifdef HAVE_LINUX_PKT_CLS_H
# include <linux/pkt_cls.h>
#endif]])
AC_CHECK_DECLS(
[TCA_SKBEDIT_MARK], [], [],
[[#ifdef HAVE_LINUX_TC_ACT_TC_SKBEDIT_H
# include <linux/tc_act/tc_skbedit.h>
#endif]])
AC_CHECK_DECLS(
[TCF_META_ID_RXHASH], [], [],
[[#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
# include <linux/tc_ematch/tc_em_meta.h>
#endif]])

AC_CHECK_MEMBERS(
[struct tc_multiq_qopt.bands,
struct tc_plug_qopt.action,
struct tc_sfq_qopt_v1.v0,
struct tc_ratespec.__reserved,
struct tc_ratespec.linklayer,
struct tc_ratespec.feature,
struct tc_ratespec.overhead,
struct tc_ratespec.addend,
struct tc_ratespec.cell_align,
struct tc_sfq_xstats.allot], [], [],
[[#ifdef HAVE_LINUX_TYPES_H
# include <linux/types.h>
#endif
#ifdef HAVE_LINUX_PKT_CLS_H
# include <linux/pkt_cls.h>
#endif]])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([pow])
AC_CHECK_LIB(m,pow)

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 man/Makefile])
AC_OUTPUT
