/*
 * ifimsg_vlan.c - interface information message parser
 * Copyright (C) 2014 Tetsumune KISO <t2mune@gmail.com>
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

#if HAVE_DECL_IFLA_VLAN_UNSPEC
/*
 * parse attributes IFLA_VLAN_*
 */
int parse_ifla_vlan(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle)
{
    struct rtattr *vlan[__IFLA_VLAN_MAX];

	parse_nested_rtattr(vlan, IFLA_VLAN_MAX, info);

#if HAVE_DECL_IFLA_VLAN_PROTOCOL
    if(vlan[IFLA_VLAN_PROTOCOL])
        if(parse_ifla_vlan_protocol(msg, mp, vlan[IFLA_VLAN_PROTOCOL], ifle))
            return(1);
#endif

    if(vlan[IFLA_VLAN_ID])
        if(parse_ifla_vlan_id(msg, mp, vlan[IFLA_VLAN_ID], ifle))
            return(1);

    if(vlan[IFLA_VLAN_EGRESS_QOS])
        if(parse_ifla_vlan_egress_qos(msg, mp, vlan[IFLA_VLAN_EGRESS_QOS], ifle))
            return(1);

    if(vlan[IFLA_VLAN_INGRESS_QOS])
        if(parse_ifla_vlan_ingress_qos(msg, mp, vlan[IFLA_VLAN_INGRESS_QOS], ifle))
            return(1);

    return(0);
}

/*
 * parse attribute IFLA_VLAN_ID
 */
int parse_ifla_vlan_id(char *msg, char **mp, struct rtattr *vlan, struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(vlan) < sizeof(ifle->vid)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }
    ifle->vid = *(unsigned short *)RTA_DATA(vlan);

    if(msg)
        *mp = add_log(msg, *mp, "vid=%hu ", ifle->vid);

    return(0);
}

/*
 * parse attribute IFLA_VLAN_EGRESS_QOS
 */
int parse_ifla_vlan_egress_qos(char *msg, char **mp, struct rtattr *vlan, struct iflist_entry *ifle)
{
    if(msg) {
        *mp = add_log(msg, *mp, "egress-qos-map(from:to)=");

        if(parse_vlan_qos_mapping(msg, mp, vlan, ifle))
            return(1);
    }

    return(0);
}

/*
 * parse attribute IFLA_VLAN_INGRESS_QOS
 */
int parse_ifla_vlan_ingress_qos(char *msg, char **mp, struct rtattr *vlan, struct iflist_entry *ifle)
{
    if(msg) {
        *mp = add_log(msg, *mp, "ingress-qos-map(from:to)=");

        if(parse_vlan_qos_mapping(msg, mp, vlan, ifle))
            return(1);
    }

    return(0);

}

/*
 * parse VLAN QoS informaton messages
 */
int parse_vlan_qos_mapping(char *msg, char **mp, struct rtattr *qos, struct iflist_entry *ifle)
{
    struct ifla_vlan_qos_mapping *map;
    int len = RTA_PAYLOAD(qos);

    *mp = add_log(msg, *mp, "(");

    for(qos = RTA_DATA(qos); RTA_OK(qos, len); qos = RTA_NEXT(qos, len)) {
        if(RTA_PAYLOAD(qos) < sizeof(*map)) {
            rec_log("error: %s: ifindex %d: payload too short",
                __func__, ifle->index);
            return(1);
        }
        map = (struct ifla_vlan_qos_mapping *)RTA_DATA(qos);

        *mp = add_log(msg, *mp, "%u:%u ", map->from, map->to);
    }

    --(*mp);
    *mp = add_log(msg, *mp, ") ");

    return(0);
}

#if HAVE_DECL_IFLA_VLAN_PROTOCOL
/*
 * parse attribute IFLA_VLAN_PROTOCOL
 */
int parse_ifla_vlan_protocol(char *msg, char **mp, struct rtattr *vlan, struct iflist_entry *ifle)
{
    unsigned short proto;

    if(RTA_PAYLOAD(vlan) < sizeof(proto)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }
    proto = ntohs(*(unsigned short *)RTA_DATA(vlan));

    if(msg)
        *mp = add_log(msg, *mp, "protocol=%s ", conv_eth_p(proto, 0));

    return(0);

}
#endif

/*
 * debug VLAN interface information messages
 */
void debug_ifla_vlan(int lev, struct rtattr *info)
{
    struct rtattr *vlan[__IFLA_VLAN_MAX];

	parse_nested_rtattr(vlan, IFLA_VLAN_MAX, info);

    if(vlan[IFLA_VLAN_ID])
        debug_rta_u16(lev+1, vlan[IFLA_VLAN_ID],
            "IFLA_VLAN_ID", NULL);

    if(vlan[IFLA_VLAN_FLAGS])
        debug_ifla_vlan_flags(lev+1, vlan[IFLA_VLAN_FLAGS],
            "IFLA_VLAN_FLAGS");

    if(vlan[IFLA_VLAN_EGRESS_QOS])
        debug_ifla_vlan_qos(lev+1, vlan[IFLA_VLAN_EGRESS_QOS],
            "IFLA_VLAN_EGRESS_QOS");

    if(vlan[IFLA_VLAN_INGRESS_QOS])
        debug_ifla_vlan_qos(lev+1, vlan[IFLA_VLAN_INGRESS_QOS],
            "IFLA_VLAN_INGRESS_QOS");

#if HAVE_DECL_IFLA_VLAN_PROTOCOL
    if(vlan[IFLA_VLAN_PROTOCOL])
        debug_rta_n16x(lev+1, vlan[IFLA_VLAN_PROTOCOL],
            "IFLA_VLAN_PROTOCOL", conv_eth_p);
#endif

    return;
}

/*
 * debug attribute IFLA_VLAN_FLAGS
 */
void debug_ifla_vlan_flags(int lev, struct rtattr *vlan, const char *name)
{
    struct ifla_vlan_flags *flags;

    if(debug_rta_len_chk(lev, vlan, name, sizeof(*flags)))
        return;

    flags = (struct ifla_vlan_flags *)RTA_DATA(vlan);
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(vlan->rta_len));
    rec_dbg(lev, "    [ ifla_flags(%d) ]", sizeof(*flags));
    rec_dbg(lev, "        flags(%d): 0x%.8x(%s)",
        sizeof(flags->flags), flags->flags,
        conv_vlan_flags(flags->flags, 1));
    rec_dbg(lev, "        mask(%d): 0x%.8x", sizeof(flags->mask), flags->mask);

    return;
}

/*
 * debug VLAN QoS informaton messages
 */
void debug_ifla_vlan_qos(int lev, struct rtattr *vlan, const char *name)
{
    struct ifla_vlan_qos_mapping *map;
    int len = RTA_PAYLOAD(vlan);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(vlan->rta_len));

    for(vlan = RTA_DATA(vlan); RTA_OK(vlan, len); vlan = RTA_NEXT(vlan, len)) {
        if(debug_rta_len_chk(lev, vlan, name, sizeof(*map)))
            return;

        map = (struct ifla_vlan_qos_mapping *)RTA_DATA(vlan);
        rec_dbg(lev+1, "%s(%hu):", name, RTA_ALIGN(vlan->rta_len));
        rec_dbg(lev+1, "    [ ifla_vlan_qos_mapping(%d) ]", sizeof(*map));
        rec_dbg(lev+1, "        from(%d): %u", sizeof(map->from), map->from);
        rec_dbg(lev+1, "        to(%d): %u", sizeof(map->to), map->to);
    }

    return;
}

/*
 * convert VLAN flags from number to string
 */
const char *conv_vlan_flags(int flags, unsigned char debug)
{
    static char list[MAX_STR_SIZE];
    unsigned len = sizeof(list);

    strncpy(list, "", len);
    if(!flags) {
        strncpy(list, "NONE", len);
        return((const char *)list);
    }
#define _VLAN_FLAGS(s) \
    if((flags & VLAN_FLAG_##s) && (len - strlen(list) - 1 > 0)) \
        (flags &= ~VLAN_FLAG_##s) ? \
            strncat(list, #s ",", len - strlen(list) - 1) : \
            strncat(list, #s, len - strlen(list) - 1);
#if HAVE_DECL_VLAN_FLAG_REORDER_HDR
    _VLAN_FLAGS(REORDER_HDR);
#endif
#if HAVE_DECL_VLAN_FLAG_GVRP
    _VLAN_FLAGS(GVRP);
#endif
#if HAVE_DECL_VLAN_FLAG_LOOSE_BINDING
    _VLAN_FLAGS(LOOSE_BINDING);
#endif
#undef _VLAN_FLAGS
    if(!strlen(list))
        strncpy(list, "UNKNOWN", len);

    return((const char *)list);
}
#endif
