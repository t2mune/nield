/*
 * nlmsg.c - netlink message parser
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
#include "nield.h"

/*
 * debug netlink messages
 */
void debug_nlmsg(int lev, struct nlmsghdr *nlh)
{
    /* logging struct nlmsghdr */
    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ nlmsghdr(%d) ]", NLMSG_HDRLEN);
    rec_dbg(lev, "    nlmsg_len(%d): %u",
        sizeof(nlh->nlmsg_len), nlh->nlmsg_len);
    rec_dbg(lev, "    nlmsg_type(%d): %hu(%s)",
        sizeof(nlh->nlmsg_type), nlh->nlmsg_type,
        debug_n2s_nlmsg_type(nlh->nlmsg_type));
    rec_dbg(lev, "    nlmsg_flags(%d): %hu",
        sizeof(nlh->nlmsg_flags), nlh->nlmsg_flags);
    rec_dbg(lev, "    nlmsg_seq(%d): %u",
        sizeof(nlh->nlmsg_seq), nlh->nlmsg_seq);
    rec_dbg(lev, "    nlmsg_pid(%d): %u",
        sizeof(nlh->nlmsg_pid), nlh->nlmsg_pid);

    return;
}

/*
 * convert a netlink message type from number to string
 */
const char *debug_n2s_nlmsg_type(int type)
{
#define _NLMSG_TYPE(s) \
    if(type == RTM_##s) \
        return #s;
    _NLMSG_TYPE(NEWLINK);
    _NLMSG_TYPE(DELLINK);
    _NLMSG_TYPE(GETLINK);
    _NLMSG_TYPE(SETLINK);
    _NLMSG_TYPE(NEWADDR);
    _NLMSG_TYPE(DELADDR);
    _NLMSG_TYPE(GETADDR);
    _NLMSG_TYPE(NEWROUTE);
    _NLMSG_TYPE(DELROUTE);
    _NLMSG_TYPE(GETROUTE);
    _NLMSG_TYPE(NEWNEIGH);
    _NLMSG_TYPE(DELNEIGH);
    _NLMSG_TYPE(GETNEIGH);
    _NLMSG_TYPE(NEWRULE);
    _NLMSG_TYPE(DELRULE);
    _NLMSG_TYPE(GETRULE);
    _NLMSG_TYPE(NEWQDISC);
    _NLMSG_TYPE(DELQDISC);
    _NLMSG_TYPE(GETQDISC);
    _NLMSG_TYPE(NEWTCLASS);
    _NLMSG_TYPE(DELTCLASS);
    _NLMSG_TYPE(GETTCLASS);
    _NLMSG_TYPE(NEWTFILTER);
    _NLMSG_TYPE(DELTFILTER);
    _NLMSG_TYPE(GETTFILTER);
    _NLMSG_TYPE(NEWACTION);
    _NLMSG_TYPE(DELACTION);
    _NLMSG_TYPE(GETACTION);
    _NLMSG_TYPE(NEWPREFIX);
    _NLMSG_TYPE(GETMULTICAST);
    _NLMSG_TYPE(GETANYCAST);
    _NLMSG_TYPE(NEWNEIGHTBL);
    _NLMSG_TYPE(GETNEIGHTBL);
    _NLMSG_TYPE(SETNEIGHTBL);
#ifdef RTM_NEWDUSEROPT
    _NLMSG_TYPE(NEWNDUSEROPT);
#endif
    _NLMSG_TYPE(NEWADDRLABEL);
    _NLMSG_TYPE(DELADDRLABEL);
    _NLMSG_TYPE(GETADDRLABEL);
#ifdef RTM_GETDCB
    _NLMSG_TYPE(GETDCB);
#endif
#ifdef RTM_SETDCB
    _NLMSG_TYPE(SETDCB);
#endif
#undef _NLMSG_TYPE
    return("UNKNOWN");
}
