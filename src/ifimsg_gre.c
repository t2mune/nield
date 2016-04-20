/*
 * ifimsg_gre.c - interface information message parser
 * Copyright (C) 2011-2016 Tetsumune KISO <t2mune@gmail.com>
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
#include "rtnetlink.h"

#if HAVE_DECL_IFLA_GRE_UNSPEC
/*
 * parse attributes IFLA_GRE_*
 */
int parse_ifla_gre(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle)
{
    struct rtattr *gre[__IFLA_GRE_MAX];

	parse_nested_rtattr(gre, IFLA_GRE_MAX, info);

    if(gre[IFLA_GRE_LOCAL])
        if(parse_ifla_gre_local(msg, mp, gre[IFLA_GRE_LOCAL], ifle))
            return(1);

    if(gre[IFLA_GRE_REMOTE])
        if(parse_ifla_gre_remote(msg, mp, gre[IFLA_GRE_REMOTE], ifle))
            return(1);

    return(0);
}

/*
 * parse attribute IFLA_GRE_LOCAL
 */
int parse_ifla_gre_local(char *msg, char **mp, struct rtattr *gre, struct iflist_entry *ifle)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    if(ifle->type == ARPHRD_ETHER)
        res = arphrd_ntop(ARPHRD_IPGRE, gre, addr, sizeof(addr));
    else
        res = arphrd_ntop(ifle->type, gre, addr, sizeof(addr));

    if(res) {
        rec_log("error: %s: IFLA_GRE_LOCAL(ifindex %d): %s",
            __func__, ifle->index,
            (res == 1) ? strerror(errno) : "payload too short");
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "source-address=%s ", addr);

    return(0);
}

/*
 * parse attribute IFLA_GRE_REMOTE
 */
int parse_ifla_gre_remote(char *msg, char **mp, struct rtattr *gre, struct iflist_entry *ifle)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    if(ifle->type == ARPHRD_ETHER)
        res = arphrd_ntop(ARPHRD_IPGRE, gre, addr, sizeof(addr));
    else
        res = arphrd_ntop(ifle->type, gre, addr, sizeof(addr));

    if(res) {
        rec_log("error: %s: IFLA_GRE_REMOTE(ifindex %d): %s",
            __func__, ifle->index,
            (res == 1) ?strerror(errno) : "payload too short");
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "destination-address=%s ", addr);

    return(0);
}

/*
 * debug GRE interface information messages
 */
void debug_ifla_gre(int lev, struct ifinfomsg *ifim, struct rtattr *info)
{
    struct rtattr *gre[__IFLA_GRE_MAX];

	parse_nested_rtattr(gre, IFLA_GRE_MAX, info);

    if(gre[IFLA_GRE_LINK])
        debug_rta_ifindex(lev+1, gre[IFLA_GRE_LINK],
            "IFLA_GRE_LINK");

    if(gre[IFLA_GRE_IFLAGS])
        debug_rta_u16x(lev+1, gre[IFLA_GRE_IFLAGS],
            "IFLA_GRE_IFLAGS", conv_gre_flags);

    if(gre[IFLA_GRE_OFLAGS])
        debug_rta_u16x(lev+1, gre[IFLA_GRE_OFLAGS],
            "IFLA_GRE_OFLAGS", conv_gre_flags);

    if(gre[IFLA_GRE_IKEY])
        debug_rta_u32x(lev+1, gre[IFLA_GRE_IKEY],
            "IFLA_GRE_IKEY", NULL);

    if(gre[IFLA_GRE_OKEY])
        debug_rta_u32x(lev+1, gre[IFLA_GRE_OKEY],
            "IFLA_GRE_OKEY", NULL);

    if(gre[IFLA_GRE_LOCAL])
        debug_rta_arphrd(lev+1, gre[IFLA_GRE_LOCAL],
            "IFLA_GRE_LOCAL",
            (ifim->ifi_type == ARPHRD_ETHER)? ARPHRD_IPGRE : ifim->ifi_type);

    if(gre[IFLA_GRE_REMOTE])
        debug_rta_arphrd(lev+1, gre[IFLA_GRE_REMOTE],
            "IFLA_GRE_REMOTE",
            (ifim->ifi_type == ARPHRD_ETHER)? ARPHRD_IPGRE : ifim->ifi_type);

    if(gre[IFLA_GRE_TTL])
        debug_rta_u8(lev+1, gre[IFLA_GRE_TTL],
            "IFLA_GRE_TTL", NULL);

    if(gre[IFLA_GRE_TOS])
        debug_rta_u8(lev+1, gre[IFLA_GRE_TOS],
            "IFLA_GRE_TOS", NULL);

    if(gre[IFLA_GRE_PMTUDISC])
        debug_rta_u8(lev+1, gre[IFLA_GRE_PMTUDISC],
            "IFLA_GRE_PMTUDISC", NULL);

#if HAVE_DECL_IFLA_GRE_ENCAP_LIMIT
    if(gre[IFLA_GRE_ENCAP_LIMIT])
        debug_rta_ignore(lev+1, gre[IFLA_GRE_ENCAP_LIMIT],
            "IFLA_GRE_ENCAP_LIMIT");

    if(gre[IFLA_GRE_FLOWINFO])
        debug_rta_ignore(lev+1, gre[IFLA_GRE_FLOWINFO],
            "IFLA_GRE_FLOWINFO");

    if(gre[IFLA_GRE_FLAGS])
        debug_rta_ignore(lev+1, gre[IFLA_GRE_FLAGS],
            "IFLA_GRE_FLAGS");
#endif

    return;
}

/*
 * convert GRE flags from number to string
 */
const char *conv_gre_flags(unsigned short flags, unsigned char debug)
{
    static char list[MAX_STR_SIZE];
    unsigned len = sizeof(list);

    strncpy(list, "", sizeof(list));
    if(!flags) {
        strncpy(list, "NONE", sizeof(list));
        return((const char *)list);
    }
#define _GRE_FLAGS(s) \
    if((flags & GRE_##s) && (len - strlen(list) - 1 > 0)) \
        (flags &= ~GRE_##s) ? \
            strncat(list, #s ",", len - strlen(list) - 1) : \
            strncat(list, #s, len - strlen(list) - 1);
    _GRE_FLAGS(CSUM);
    _GRE_FLAGS(ROUTING);
    _GRE_FLAGS(KEY);
    _GRE_FLAGS(SEQ);
    _GRE_FLAGS(STRICT);
#undef _GRE_FLAGS
    if(!strlen(list))
        strncpy(list, "UNKNOWN", len);

    return((const char *)list);
}
#endif
