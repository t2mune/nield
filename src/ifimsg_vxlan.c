/*
 * ifimsg_vxlan.c - interface information message parser
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
#include "nield.h"
#include "rtnetlink.h"

#if HAVE_DECL_IFLA_VXLAN_UNSPEC
/*
 * parse attributes IFLA_VLXAN_*
 */
int parse_ifla_vxlan(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle)
{
    struct rtattr *vxlan[__IFLA_VXLAN_MAX];

	parse_nested_rtattr(vxlan, IFLA_VXLAN_MAX, info);

    if(vxlan[IFLA_VXLAN_ID])
        if(parse_ifla_vxlan_id(msg, mp, vxlan[IFLA_VXLAN_ID], ifle))
            return(1);

    if(vxlan[IFLA_VXLAN_LINK])
        if(parse_ifla_vxlan_link(msg, mp, vxlan[IFLA_VXLAN_LINK], ifle))
            return(1);

    if(vxlan[IFLA_VXLAN_LOCAL])
        if(parse_ifla_vxlan_local(msg, mp, vxlan[IFLA_VXLAN_LOCAL], ifle, AF_INET))
            return(1);

#if HAVE_DECL_IFLA_VXLAN_GROUP6
    if(vxlan[IFLA_VXLAN_LOCAL6])
        if(parse_ifla_vxlan_local(msg, mp, vxlan[IFLA_VXLAN_LOCAL6], ifle, AF_INET6))
            return(1);
#endif

    if(vxlan[IFLA_VXLAN_PORT_RANGE])
        if(parse_ifla_vxlan_port_range(msg, mp, vxlan[IFLA_VXLAN_PORT_RANGE], ifle))
            return(1);

#if HAVE_DECL_IFLA_VXLAN_REMOTE
    if(vxlan[IFLA_VXLAN_REMOTE])
        if(parse_ifla_vxlan_group(msg, mp, vxlan[IFLA_VXLAN_REMOTE], ifle, AF_INET))
            return(1);
#endif
#if HAVE_DECL_IFLA_VXLAN_GROUP
    if(vxlan[IFLA_VXLAN_GROUP])
        if(parse_ifla_vxlan_group(msg, mp, vxlan[IFLA_VXLAN_GROUP], ifle, AF_INET))
            return(1);
#endif
#if HAVE_DECL_IFLA_VXLAN_GROUP6
    if(vxlan[IFLA_VXLAN_GROUP6])
        if(parse_ifla_vxlan_group(msg, mp, vxlan[IFLA_VXLAN_GROUP6], ifle, AF_INET6))
            return(1);
#endif
#if HAVE_DECL_IFLA_VXLAN_PORT
    if(vxlan[IFLA_VXLAN_PORT])
        if(parse_ifla_vxlan_port(msg, mp, vxlan[IFLA_VXLAN_PORT], ifle))
            return(1);
#endif

    return(0);
}

/*
 * parse attribute IFLA_VXLAN_ID
 */
int parse_ifla_vxlan_id(char *msg, char **mp, struct rtattr *vxlan, struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(vxlan) < sizeof(unsigned)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "vni=%u ", *(unsigned *)RTA_DATA(vxlan));

    return(0);
}

/*
 * parse attribute IFLA_VXLAN_LINK
 */
int parse_ifla_vxlan_link(char *msg, char **mp, struct rtattr *vxlan, struct iflist_entry *ifle)
{
    char name[IFNAMSIZ];

    if(RTA_PAYLOAD(vxlan) < sizeof(int)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }
    if_indextoname_from_lists(*(int *)RTA_DATA(vxlan), name);

    if(msg)
        *mp = add_log(msg, *mp, "link=%s ", name);

    return(0);
}

/*
 * parse attribute IFLA_VXLAN_LOCAL/IFLA_VXLAN_LOCAL6
 */
int parse_ifla_vxlan_local(char *msg, char **mp, struct rtattr *vxlan,
    struct iflist_entry *ifle, unsigned short family)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = inet_ntop_ifa(family, vxlan, addr, sizeof(addr));
    if(res) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "source-address=%s ", addr);

    return(0);
}

/*
 * parse attribute IFLA_VXLAN_PORT_RANGE
 */
int parse_ifla_vxlan_port_range(char *msg, char **mp, struct rtattr *vxlan,
    struct iflist_entry *ifle)
{
    struct ifla_vxlan_port_range *range;

    if(RTA_PAYLOAD(vxlan) < sizeof(*range)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    range = (struct ifla_vxlan_port_range *)RTA_DATA(vxlan);

    if(msg)
        *mp = add_log(msg, *mp, "source-port=%hu-%hu ", ntohs(range->low), ntohs(range->high));

    return(0);
}

/*
 * parse attribute IFLA_VXLAN_PORT
 */
int parse_ifla_vxlan_port(char *msg, char **mp, struct rtattr *vxlan,
    struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(vxlan) < sizeof(unsigned short)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "destination-port=%hu ", ntohs(*(unsigned short *)RTA_DATA(vxlan)));

    return(0);
}

/*
 * parse attribute IFLA_VXLAN_REMOTE/IFLA_VXLAN_GROUP/IFLA_VXLAN_GROUP6
 */
int parse_ifla_vxlan_group(char *msg, char **mp, struct rtattr *vxlan,
    struct iflist_entry *ifle, unsigned short family)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = inet_ntop_ifa(family, vxlan, addr, sizeof(addr));
    if(res) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "destination-address=%s ", addr);

    return(0);
}

/*
 * debug VXLAN interface information messages
 */
void debug_ifla_vxlan(int lev, struct rtattr *info)
{
    struct rtattr *vxlan[__IFLA_VXLAN_MAX];

	parse_nested_rtattr(vxlan, IFLA_VXLAN_MAX, info);

    if(vxlan[IFLA_VXLAN_ID])
        debug_rta_u32(lev+1, vxlan[IFLA_VXLAN_ID],
            "IFLA_VXLAN_ID", NULL);

#if HAVE_DECL_IFLA_VXLAN_REMOTE
    if(vxlan[IFLA_VXLAN_REMOTE])
        debug_rta_af(lev+1, vxlan[IFLA_VXLAN_REMOTE],
            "IFLA_VXLAN_REMOTE", AF_INET);
#endif
#if HAVE_DECL_IFLA_VXLAN_GROUP
    if(vxlan[IFLA_VXLAN_GROUP])
        debug_rta_af(lev+1, vxlan[IFLA_VXLAN_GROUP],
            "IFLA_VXLAN_GROUP", AF_INET);
#endif

    if(vxlan[IFLA_VXLAN_LINK])
        debug_rta_ifindex(lev+1, vxlan[IFLA_VXLAN_LINK],
            "IFLA_VXLAN_LINK");

    if(vxlan[IFLA_VXLAN_LOCAL])
        debug_rta_af(lev+1, vxlan[IFLA_VXLAN_LOCAL],
            "IFLA_VXLAN_LOCAL", AF_INET);

    if(vxlan[IFLA_VXLAN_TTL])
        debug_rta_u8(lev+1, vxlan[IFLA_VXLAN_TTL],
            "IFLA_VXLAN_TTL", NULL);

    if(vxlan[IFLA_VXLAN_TOS])
        debug_rta_u8(lev+1, vxlan[IFLA_VXLAN_TOS],
            "IFLA_VXLAN_TOS", NULL);

    if(vxlan[IFLA_VXLAN_LEARNING])
        debug_rta_u8(lev+1, vxlan[IFLA_VXLAN_LEARNING],
            "IFLA_VXLAN_LEARNING", NULL);

    if(vxlan[IFLA_VXLAN_AGEING])
        debug_rta_u32(lev+1, vxlan[IFLA_VXLAN_AGEING],
            "IFLA_VXLAN_AGEING", NULL);

    if(vxlan[IFLA_VXLAN_LIMIT])
        debug_rta_u32(lev+1, vxlan[IFLA_VXLAN_LIMIT],
            "IFLA_VXLAN_LIMIT", NULL);

    if(vxlan[IFLA_VXLAN_PORT_RANGE])
        debug_ifla_vxlan_port_range(lev+1, vxlan[IFLA_VXLAN_PORT_RANGE],
            "IFLA_VXLAN_PORT_RANGE");

#if HAVE_DECL_IFLA_VXLAN_PROXY
    if(vxlan[IFLA_VXLAN_PROXY])
        debug_rta_u8(lev+1, vxlan[IFLA_VXLAN_PROXY],
            "IFLA_VXLAN_PROXY", NULL);

    if(vxlan[IFLA_VXLAN_RSC])
        debug_rta_u8(lev+1, vxlan[IFLA_VXLAN_RSC],
            "IFLA_VXLAN_RSC", NULL);

    if(vxlan[IFLA_VXLAN_L2MISS])
        debug_rta_u8(lev+1, vxlan[IFLA_VXLAN_L2MISS],
            "IFLA_VXLAN_L2MISS", NULL);

    if(vxlan[IFLA_VXLAN_L3MISS])
        debug_rta_u8(lev+1, vxlan[IFLA_VXLAN_L3MISS],
            "IFLA_VXLAN_L3MISS", NULL);
#endif
#if HAVE_DECL_IFLA_VXLAN_PORT
    if(vxlan[IFLA_VXLAN_PORT])
        debug_rta_n16(lev+1, vxlan[IFLA_VXLAN_PORT],
            "IFLA_VXLAN_PORT", NULL);
#endif
#if HAVE_DECL_IFLA_VXLAN_GROUP6
    if(vxlan[IFLA_VXLAN_GROUP6])
        debug_rta_af(lev+1, vxlan[IFLA_VXLAN_GROUP6],
            "IFLA_VXLAN_GROUP6", AF_INET6);

    if(vxlan[IFLA_VXLAN_LOCAL6])
        debug_rta_af(lev+1, vxlan[IFLA_VXLAN_LOCAL6],
            "IFLA_VXLAN_LOCAL6", AF_INET6);
#endif

    return;
}

/*
 * debug attribute IFLA_VXLAN_PORT_RANGE
 */
void debug_ifla_vxlan_port_range(int lev, struct rtattr *vxlan, const char *name)
{
    struct ifla_vxlan_port_range *range;

    if(debug_rta_len_chk(lev, vxlan, name, sizeof(*range)))
        return;

    range = (struct ifla_vxlan_port_range *)RTA_DATA(vxlan);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(vxlan->rta_len));
    rec_dbg(lev, "    [ ifla_vxlan_port_range(%d) ]", sizeof(*range));
    rec_dbg(lev, "        low(%d): %hu", sizeof(range->low), ntohs(range->low));
    rec_dbg(lev, "        high(%d): %hu", sizeof(range->high), ntohs(range->high));

    return;
}
#endif
