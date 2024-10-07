/*
 * rtnetlink.h - route attribute parser
 * Copyright (C) 2011-2024 Tetsumune KISO <t2mune@gmail.com>
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
#ifndef _RTNETLINK_
#define _RTNETLINK_

/*
 * parse route attributes
 */
static inline void parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta, int len,
	unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if (type <= max)
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

static inline void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	parse_rtattr_flags(tb, max, rta, len, 0);
}

/*
 * parse route attributes nested
 */
static inline void parse_nested_rtattr(struct rtattr *tb[], int max, struct rtattr *rta)
{
	parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

#ifndef IFLA_RTA
#define IFLA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif

#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif

/*
 * parse interface infromation attributes
 */
static inline void parse_ifinfo(struct rtattr *tb[], struct nlmsghdr *nlh)
{
	struct ifinfomsg *ifim = NLMSG_DATA(nlh);
	parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifim), IFLA_PAYLOAD(nlh), 1<<15);
}

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

/*
 * parse neighbor discovery attributes
 */
static inline void parse_ndisc(struct rtattr *tb[], struct nlmsghdr *nlh)
{
	struct ndmsg *ndm = NLMSG_DATA(nlh);
	parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), NDA_PAYLOAD(nlh));
}

#ifndef IFA_RTA
#define IFA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#endif

#ifndef IFA_PAYLOAD
#define IFA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
#endif

/*
 * parse interface address attributes
 */
static inline void parse_ifaddr(struct rtattr *tb[], struct nlmsghdr *nlh)
{
	struct ifaddrmsg *ifam = NLMSG_DATA(nlh);
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifam), IFA_PAYLOAD(nlh));
}

#ifdef HAVE_LINUX_FIB_RULES_H
#ifndef FRA_RTA
#define FRA_RTA(r) \
	((struct rtattr *)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct fib_rule_hdr))))
#endif

#ifndef FRA_PAYLOAD
#define FRA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct fib_rule_hdr))
#endif

/*
 * parse fib rule attributes
 */
static inline void parse_frule(struct rtattr *tb[], struct nlmsghdr *nlh)
{
	struct fib_rule_hdr *frh = NLMSG_DATA(nlh);
	parse_rtattr(tb, FRA_MAX, FRA_RTA(frh), FRA_PAYLOAD(nlh));
}
#endif

#ifndef TCA_RTA
#define TCA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))
#endif

#ifndef TCA_PAYLOAD
#define TCA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcmsg))
#endif

/*
 * parse traffic control attributes
 */
static inline void parse_tc(struct rtattr *tb[], struct nlmsghdr *nlh)
{
	struct tcmsg *tcm = NLMSG_DATA(nlh);
	parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), TCA_PAYLOAD(nlh));
}

#ifndef TA_RTA
#define TA_RTA(r)  \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcamsg))))
#endif

#ifndef TA_PAYLOAD
#define TA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcamsg))
#endif

/*
 * parse traffic control attributes
 */
static inline void parse_tca(struct rtattr *tb[], struct nlmsghdr *nlh)
{
	struct tcamsg *tcam = NLMSG_DATA(nlh);
	parse_rtattr(tb, TCAA_MAX, TA_RTA(tcam), TA_PAYLOAD(nlh));
}
#endif
