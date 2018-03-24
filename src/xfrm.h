/*
 * xfrm.h - xfrm attribute parser
 * Copyright (C) 2018 Tetsumune KISO <t2mune@gmail.com>
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
#ifndef _XFRM_
#define _XFRM_

#ifndef XFRMGRP_ACQUIRE
#define XFRMGRP_ACQUIRE (1<<(XFRMNLGRP_ACQUIRE-1))
#endif

#ifndef XFRMGRP_EXPIRE
#define XFRMGRP_EXPIRE (1<<(XFRMNLGRP_EXPIRE-1))
#endif

#ifndef XFRMGRP_SA
#define XFRMGRP_SA (1<<(XFRMNLGRP_SA-1))
#endif

#ifndef XFRMGRP_POLICY
#define XFRMGRP_POLICY (1<<(XFRMNLGRP_POLICY-1))
#endif

#ifndef XFRMGRP_AEVENTS
#define XFRMGRP_AEVENTS (1<<(XFRMNLGRP_AEVENTS-1))
#endif

#ifndef XFRMGRP_REPORT
#define XFRMGRP_REPORT (1<<(XFRMNLGRP_REPORT-1))
#endif

#ifndef XFRMGRP_MIGRATE
#define XFRMGRP_MIGRATE (1<<(XFRMNLGRP_MIGRATE-1))
#endif

#ifndef XFRMGRP_MAPPING
#define XFRMGRP_MAPPING (1<<(XFRMNLGRP_MAPPING-1))
#endif

/*
 * parse route attributes
 */
/*
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
*/

/*
#ifndef IFLA_RTA
#define IFLA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif

#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif
*/

/*
 * parse interface infromation attributes
 */
/*
static inline void parse_ifinfo(struct rtattr *tb[], struct nlmsghdr *nlh)
{
	struct ifinfomsg *ifim = NLMSG_DATA(nlh);
	parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifim), IFLA_PAYLOAD(nlh), 1<<15);
}
*/

#endif
