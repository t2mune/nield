/*
 * ifimsg_macvlan.c - interface information message parser
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

#if HAVE_DECL_IFLA_MACVLAN_UNSPEC
/*
 * parse IFLA_MACVLAN_*
 */
int parse_ifla_macvlan(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle)
{
    struct rtattr *macvlan[__IFLA_MACVLAN_MAX];

	parse_nested_rtattr(macvlan, IFLA_MACVLAN_MAX, info);

    if(macvlan[IFLA_MACVLAN_MODE])
        if(parse_ifla_macvlan_mode(msg, mp, macvlan[IFLA_MACVLAN_MODE], ifle))
            return(1);

    return(0);
}

/*
 * parse attribute IFLA_MACVLAN_MODE
 */
int parse_ifla_macvlan_mode(char *msg, char **mp, struct rtattr *macvlan,
    struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(macvlan) < sizeof(unsigned)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "mode=%s ",
            conv_macvlan_mode(*(unsigned *)RTA_DATA(macvlan), 0));

    return(0);
}

/*
 * debug MACVLAN interface information messages
 */
void debug_ifla_macvlan(int lev, struct rtattr *info)
{
    struct rtattr *macvlan[__IFLA_MACVLAN_MAX];

	parse_nested_rtattr(macvlan, IFLA_MACVLAN_MAX, info);

    if(macvlan[IFLA_MACVLAN_MODE])
        debug_rta_u32x(lev+1, macvlan[IFLA_MACVLAN_MODE],
            "IFLA_MACVLAN_MODE", conv_macvlan_mode);

#if HAVE_DECL_IFLA_MACVLAN_FLAGS
    if(macvlan[IFLA_MACVLAN_FLAGS])
        debug_rta_ignore(lev+1, macvlan[IFLA_MACVLAN_FLAGS],
            "IFLA_MACVLAN_FLAGS");
#endif
}

/*
 * convert MACVLAN flags from number to string
 */
const char *conv_macvlan_mode(unsigned mode, unsigned char debug)
{
#define _MACVLAN_MODE(s1, s2) \
    if(mode == MACVLAN_MODE_##s1) \
        return(debug ? #s1 : #s2);
    _MACVLAN_MODE(PRIVATE, private);
    _MACVLAN_MODE(VEPA, vepa);
    _MACVLAN_MODE(BRIDGE, bridge);
#if HAVE_DECL_MACVLAN_MODE_PASSTHRU
    _MACVLAN_MODE(PASSTHRU, passthru);
#endif
#undef _MACVLAN_MODE
    return(debug ? "UNKNOWN" : "unknown");
}
#endif
