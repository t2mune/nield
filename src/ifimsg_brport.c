/*
 * ifimsg_brport.c - interface information message parser
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

#if HAVE_DECL_IFLA_BRPORT_UNSPEC
/*
 * parse RTM_NEWLINK for PF_BRIDGE
 */
void parse_rtm_newlink_bridge(struct iflist_entry *ifle,
    struct iflist_entry *ifle_tmp, struct rtattr *ifla[])
{
    if(!ifle)
        return;

    if(!ifle->br_attached) {
        ifle->br_attached = 1;
        ifle->index_master = ifle_tmp->index_master;
        rec_log("interface %s attached to bridge %s",
            ifle->name, ifle_tmp->name_master);
        strncpy(ifle->name_master, ifle_tmp->name_master, IFNAMSIZ);
    }

    if(ifle->br_state != ifle_tmp->br_state) {
        rec_log("bridge %s port %s stp state changed to %s",
                ifle->name_master, ifle->name,
                conv_br_state(ifle_tmp->br_state, 0));
        ifle->br_state = ifle_tmp->br_state;
    }

    return;
}

/*
 * parse RTM_DELLINK for bridge
 */
void parse_rtm_dellink_bridge(struct iflist_entry *ifle)
{
    if(ifle && ifle->br_attached) {
        ifle->br_attached = 0;
        rec_log("interface %s detached from bridge %s",
            ifle->name, ifle->name_master);
        strncpy(ifle->name_master, "", IFNAMSIZ);
    }

    return;
}

/*
 * parse attributes IFLA_BRPORT_*
 */
int parse_ifla_brport(struct rtattr *ifla, struct iflist_entry *ifle)
{
    struct rtattr *brp[__IFLA_BRPORT_MAX];

	parse_nested_rtattr(brp, IFLA_BRPORT_MAX, ifla);

    if(brp[IFLA_BRPORT_STATE])
        parse_ifla_brport_state(brp[IFLA_BRPORT_STATE], ifle);

    return(0);
}

/*
 * psrse attribute IFLA_BRPORT_STATE
 */
int parse_ifla_brport_state(struct rtattr *brp, struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(brp) < sizeof(unsigned char)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    ifle->br_state = *(unsigned char *)RTA_DATA(brp);

    return(0);
}

/*
 * debug attributes IFLA_BRPORT_*
 */
void debug_ifla_brport(int lev, struct rtattr *ifla)
{
    struct rtattr *brp[__IFLA_BRPORT_MAX];

	parse_nested_rtattr(brp, IFLA_BRPORT_MAX, ifla);

    if(brp[IFLA_BRPORT_STATE])
        debug_rta_u8(lev+1, brp[IFLA_BRPORT_STATE],
            "IFLA_BRPORT_STATE", conv_br_state);

    if(brp[IFLA_BRPORT_PRIORITY])
        debug_rta_u16(lev+1, brp[IFLA_BRPORT_PRIORITY],
            "IFLA_BRPORT_PRIORITY", NULL);

    if(brp[IFLA_BRPORT_COST])
        debug_rta_u32(lev+1, brp[IFLA_BRPORT_COST],
            "IFLA_BRPORT_COST", NULL);

    if(brp[IFLA_BRPORT_MODE])
        debug_rta_u8(lev+1, brp[IFLA_BRPORT_MODE],
            "IFLA_BRPORT_MODE", NULL);

    if(brp[IFLA_BRPORT_GUARD])
        debug_rta_u8(lev+1, brp[IFLA_BRPORT_GUARD],
            "IFLA_BRPORT_GUARD", NULL);

    if(brp[IFLA_BRPORT_PROTECT])
        debug_rta_u8(lev+1, brp[IFLA_BRPORT_PROTECT],
            "IFLA_BRPORT_PROTECT", NULL);

    if(brp[IFLA_BRPORT_FAST_LEAVE])
        debug_rta_u8(lev+1, brp[IFLA_BRPORT_FAST_LEAVE],
            "IFLA_BRPORT_FAST_LEAVE", NULL);

#if HAVE_DECL_IFLA_BRPORT_LEARNING
    if(brp[IFLA_BRPORT_LEARNING])
        debug_rta_u8(lev+1, brp[IFLA_BRPORT_LEARNING],
            "IFLA_BRPORT_LEARNING", NULL);

    if(brp[IFLA_BRPORT_UNICAST_FLOOD])
        debug_rta_u8(lev+1, brp[IFLA_BRPORT_UNICAST_FLOOD],
            "IFLA_BRPORT_UNICAST_FLOOD", NULL);
#endif

    return;
}

/*
 * convert bridge port state from number to string
 */
const char *conv_br_state(unsigned char state, unsigned char debug)
{
#define _BR_STATE(s1, s2) \
    if(state == BR_STATE_##s1) \
        return(debug ? #s1 : #s2);
    _BR_STATE(DISABLED, disabled);
    _BR_STATE(LISTENING, listening);
    _BR_STATE(LEARNING, learning);
    _BR_STATE(FORWARDING, forwarding);
    _BR_STATE(BLOCKING, blocking);
#undef _BR_STATE
    return("UNKNOWN");
}
#endif
