/*
 * ifimsg_bond.c - interface information message parser
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

#if HAVE_DECL_IFLA_BOND_UNSPEC
/*
 * parse attributes IFLA_BOND_*
 */
int parse_ifla_bond(char *msg, char **mp,
    struct rtattr *info, struct iflist_entry *ifle)
{
    struct rtattr *bond[__IFLA_BOND_MAX];

	parse_nested_rtattr(bond, IFLA_BOND_MAX, info);

    if(bond[IFLA_BOND_MODE])
        if(parse_ifla_bond_mode(msg, mp, bond[IFLA_BOND_MODE], ifle))
            return(1);

    if(bond[IFLA_BOND_XMIT_HASH_POLICY])
        if(parse_ifla_bond_xmit_hash_policy(msg, mp,
            bond[IFLA_BOND_XMIT_HASH_POLICY], ifle))
            return(1);

    return(0);
}

/*
 * parse attribute IFLA_BOND_MODE
 */
int parse_ifla_bond_mode(char *msg, char **mp,
    struct rtattr *bond, struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(bond) < sizeof(unsigned char)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "mode=%s ",
            conv_bond_mode(*(unsigned char *)RTA_DATA(bond), 0));

    return(0);
}

/*
 * parse attribute IFLA_BOND_XMIT_HASH_POLICY
 */
int parse_ifla_bond_xmit_hash_policy(char *msg, char **mp,
    struct rtattr *bond, struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(bond) < sizeof(unsigned char)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }

    if(msg)
        *mp = add_log(msg, *mp, "hash=%s ",
            conv_bond_xmit_policy(*(unsigned char *)RTA_DATA(bond), 0));

    return(0);
}
/*
 * debug BOND interface information messages
 */
void debug_ifla_bond(int lev, struct rtattr *info)
{
    struct rtattr *bond[__IFLA_BOND_MAX];

	parse_nested_rtattr(bond, IFLA_BOND_MAX, info);

    if(bond[IFLA_BOND_MODE])
        debug_rta_u8(lev+1, bond[IFLA_BOND_MODE],
            "IFLA_BOND_MODE", conv_bond_mode);

    if(bond[IFLA_BOND_ACTIVE_SLAVE])
        debug_rta_ifindex(lev+1, bond[IFLA_BOND_ACTIVE_SLAVE],
            "IFLA_BOND_ACTIVE_SLAVE");

#if HAVE_DECL_IFLA_BOND_MIIMON
    if(bond[IFLA_BOND_MIIMON])
        debug_rta_u32(lev+1, bond[IFLA_BOND_MIIMON],
            "IFLA_BOND_MIIMON", NULL);

    if(bond[IFLA_BOND_UPDELAY])
        debug_rta_u32(lev+1, bond[IFLA_BOND_UPDELAY],
            "IFLA_BOND_UPDELAY", NULL);

    if(bond[IFLA_BOND_DOWNDELAY])
        debug_rta_u32(lev+1, bond[IFLA_BOND_DOWNDELAY],
            "IFLA_BOND_DOWNDELAY", NULL);

    if(bond[IFLA_BOND_USE_CARRIER])
        debug_rta_u8(lev+1, bond[IFLA_BOND_USE_CARRIER],
            "IFLA_BOND_USE_CARRIER", NULL);

    if(bond[IFLA_BOND_ARP_INTERVAL])
        debug_rta_u32(lev+1, bond[IFLA_BOND_ARP_INTERVAL],
            "IFLA_BOND_ARP_INTERVAL", NULL);

    if(bond[IFLA_BOND_ARP_IP_TARGET])
        debug_ifla_bond_arp_ip_target(lev+1, bond[IFLA_BOND_ARP_IP_TARGET],
            "IFLA_BOND_ARP_IP_TARGET");

    if(bond[IFLA_BOND_ARP_VALIDATE])
        debug_rta_u32(lev+1, bond[IFLA_BOND_ARP_VALIDATE],
            "IFLA_BOND_ARP_VALIDATE", NULL);

    if(bond[IFLA_BOND_ARP_ALL_TARGETS])
        debug_rta_u32(lev+1, bond[IFLA_BOND_ARP_ALL_TARGETS],
            "IFLA_BOND_ARP_ALL_TARGETS", NULL);

    if(bond[IFLA_BOND_PRIMARY])
        debug_rta_u32(lev+1, bond[IFLA_BOND_PRIMARY],
            "IFLA_BOND_PRIMARY", NULL);

    if(bond[IFLA_BOND_PRIMARY_RESELECT])
        debug_rta_u8(lev+1, bond[IFLA_BOND_PRIMARY_RESELECT],
            "IFLA_BOND_PRIMARY_RESELECT", NULL);

    if(bond[IFLA_BOND_FAIL_OVER_MAC])
        debug_rta_u8(lev+1, bond[IFLA_BOND_FAIL_OVER_MAC],
            "IFLA_BOND_FAIL_OVER_MAC", NULL);

    if(bond[IFLA_BOND_XMIT_HASH_POLICY])
        debug_rta_u8(lev+1, bond[IFLA_BOND_XMIT_HASH_POLICY],
            "IFLA_BOND_XMIT_HASH_POLICY", conv_bond_xmit_policy);

    if(bond[IFLA_BOND_RESEND_IGMP])
        debug_rta_u32(lev+1, bond[IFLA_BOND_RESEND_IGMP],
            "IFLA_BOND_RESEND_IGMP", NULL);

    if(bond[IFLA_BOND_NUM_PEER_NOTIF])
        debug_rta_u8(lev+1, bond[IFLA_BOND_NUM_PEER_NOTIF],
            "IFLA_BOND_NUM_PEER_NOTIF", NULL);

    if(bond[IFLA_BOND_ALL_SLAVES_ACTIVE])
        debug_rta_u8(lev+1, bond[IFLA_BOND_ALL_SLAVES_ACTIVE],
            "IFLA_BOND_ALL_SLAVES_ACTIVE", NULL);

    if(bond[IFLA_BOND_MIN_LINKS])
        debug_rta_u32(lev+1, bond[IFLA_BOND_MIN_LINKS],
            "IFLA_BOND_MIN_LINKS", NULL);

    if(bond[IFLA_BOND_LP_INTERVAL])
        debug_rta_u32(lev+1, bond[IFLA_BOND_LP_INTERVAL],
            "IFLA_BOND_LP_INTERVAL", NULL);

    if(bond[IFLA_BOND_PACKETS_PER_SLAVE])
        debug_rta_u32(lev+1, bond[IFLA_BOND_PACKETS_PER_SLAVE],
            "IFLA_BOND_PACKETS_PER_SLAVE", NULL);

    if(bond[IFLA_BOND_AD_LACP_RATE])
        debug_rta_u8(lev+1, bond[IFLA_BOND_AD_LACP_RATE],
            "IFLA_BOND_AD_LACP_RATE", NULL);

    if(bond[IFLA_BOND_AD_SELECT])
        debug_rta_u8(lev+1, bond[IFLA_BOND_AD_SELECT],
            "IFLA_BOND_AD_SELECT", NULL);

    if(bond[IFLA_BOND_AD_INFO])
        debug_ifla_bond_ad_info(lev+1, bond[IFLA_BOND_AD_INFO],
            "IFLA_BOND_AD_INFO");
#endif

    return;
}

#if HAVE_DECL_IFLA_BOND_MIIMON
/*
 * debug attribute IFLA_BOND_ARP_IP_TARGET
 */
void debug_ifla_bond_arp_ip_target(int lev, struct rtattr *bond, const char *name)
{
    int i;
    char addr[INET_ADDRSTRLEN] = "";
    char target[INET_ADDRSTRLEN * BOND_MAX_ARP_TARGETS] = "";
    struct rtattr *e[BOND_MAX_ARP_TARGETS + 1];

    parse_nested_rtattr(e, BOND_MAX_ARP_TARGETS, bond);

    for(i = 0; i < BOND_MAX_ARP_TARGETS; i++) {
        if(!e[i])
            break;
        inet_ntop(AF_INET, RTA_DATA(e[i]), addr, sizeof(addr));
        strncat(target, addr, sizeof(addr));
        strcat(target, ",");
    }
    if(strlen(target) > 0)
        target[strlen(target) - 1] = '\0';

    rec_dbg(lev, "%s(%hu): %s",
        name, RTA_ALIGN(bond->rta_len), target);

    return;
}

/*
 * debug attribute IFLA_BOND_AD_INFO
 */
void debug_ifla_bond_ad_info(int lev, struct rtattr *bond, const char *name)
{
    struct rtattr *info[__IFLA_BOND_AD_INFO_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(bond->rta_len));

	parse_nested_rtattr(info, IFLA_BOND_AD_INFO_MAX, bond);

    if(info[IFLA_BOND_AD_INFO_AGGREGATOR])
        debug_rta_u16(lev+1, info[IFLA_BOND_AD_INFO_AGGREGATOR],
            "IFLA_BOND_AD_INFO_AGGREGATOR", NULL);

    if(info[IFLA_BOND_AD_INFO_NUM_PORTS])
        debug_rta_u16(lev+1, info[IFLA_BOND_AD_INFO_NUM_PORTS],
            "IFLA_BOND_AD_INFO_NUM_PORTS", NULL);

    if(info[IFLA_BOND_AD_INFO_ACTOR_KEY])
        debug_rta_u16(lev+1, info[IFLA_BOND_AD_INFO_ACTOR_KEY],
            "IFLA_BOND_AD_INFO_ACTOR_KEY", NULL);

    if(info[IFLA_BOND_AD_INFO_PARTNER_KEY])
        debug_rta_u16(lev+1, info[IFLA_BOND_AD_INFO_PARTNER_KEY],
            "IFLA_BOND_AD_INFO_PARTNER_KEY", NULL);

    if(info[IFLA_BOND_AD_INFO_PARTNER_MAC])
        debug_rta_arphrd(lev+1, info[IFLA_BOND_AD_INFO_PARTNER_MAC],
            "IFLA_BOND_AD_INFO_PARTNER_MAC", ARPHRD_ETHER);

    return;
}

/*
 * debug attribute IFLA_BOND_SLAVE
 */
void debug_ifla_bond_slave(int lev, struct rtattr *bond)
{
    struct rtattr *info[__IFLA_BOND_SLAVE_MAX];

	parse_nested_rtattr(info, IFLA_BOND_SLAVE_MAX, bond);

    if(info[IFLA_BOND_SLAVE_STATE])
        debug_rta_u8(lev+1, info[IFLA_BOND_SLAVE_STATE],
            "IFLA_BOND_SLAVE_STATE", conv_bond_state);

    if(info[IFLA_BOND_SLAVE_MII_STATUS])
        debug_rta_u8(lev+1, info[IFLA_BOND_SLAVE_MII_STATUS],
            "IFLA_BOND_SLAVE_MII_STATUS", conv_bond_link);

    if(info[IFLA_BOND_SLAVE_LINK_FAILURE_COUNT])
        debug_rta_u32(lev+1, info[IFLA_BOND_SLAVE_LINK_FAILURE_COUNT],
            "IFLA_BOND_SLAVE_LINK_FAILURE_COUNT", NULL);

    if(info[IFLA_BOND_SLAVE_PERM_HWADDR])
        debug_rta_arphrd(lev+1, info[IFLA_BOND_SLAVE_PERM_HWADDR],
            "IFLA_BOND_SLAVE_PERM_HWADDR", ARPHRD_ETHER);

    if(info[IFLA_BOND_SLAVE_QUEUE_ID])
        debug_rta_u16(lev+1, info[IFLA_BOND_SLAVE_QUEUE_ID],
            "IFLA_BOND_SLAVE_QUEUE_ID", NULL);

    if(info[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID])
        debug_rta_u16(lev+1, info[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID],
            "IFLA_BOND_SLAVE_AD_AGGREGATOR_ID", NULL);

    return;
}
#endif

/*
 * convert bonding mode from number to string
 */
const char *conv_bond_mode(unsigned char mode, unsigned char debug)
{
#define _BOND_MODE(s1, s2) \
    if(mode == BOND_MODE_##s1) \
        return(debug ? #s1 : #s2);
    _BOND_MODE(ROUNDROBIN, balance-rr);
    _BOND_MODE(ACTIVEBACKUP, active-backup);
    _BOND_MODE(XOR, balance-xor);
    _BOND_MODE(BROADCAST, broadcast);
    _BOND_MODE(8023AD, 802.3ad);
    _BOND_MODE(TLB, balance-tlb);
    _BOND_MODE(ALB, balance-alb);
#undef _BOND_MODE
    return("UNKNOWN");
}

#if HAVE_DECL_IFLA_BOND_MIIMON
/*
 * convert bonding xmit hash policy from number to string
 */
const char *conv_bond_xmit_policy(unsigned char policy, unsigned char debug)
{
#define _BOND_XMIT_POLICY(s1, s2) \
    if(policy == BOND_XMIT_POLICY_##s1) \
        return(debug ? #s1 : #s2);
    _BOND_XMIT_POLICY(LAYER2, layer2);
    _BOND_XMIT_POLICY(LAYER34, layer3+4);
    _BOND_XMIT_POLICY(LAYER23, layer2+3);
    _BOND_XMIT_POLICY(ENCAP23, encap2+3);
    _BOND_XMIT_POLICY(ENCAP34, encap3+4);
#undef _BOND_XMIT_POLICY
    return("UNKNOWN");
}

/*
 * convert bonding slave state from number to string
 */
const char *conv_bond_state(unsigned char state, unsigned char debug)
{
#define _BOND_STATE(s1, s2) \
    if(state == BOND_STATE_##s1) \
        return(debug ? #s1 : #s2);
    _BOND_STATE(ACTIVE, active);
    _BOND_STATE(BACKUP, backup);
#undef _BOND_STATE
    return("UNKNOWN");
}

/*
 * convert bonding slave mii-status from number to string
 */
const char *conv_bond_link(unsigned char link, unsigned char debug)
{
#define _BOND_LINK(s1, s2) \
    if(link == BOND_LINK_##s1) \
        return(debug ? #s1 : #s2);
    _BOND_LINK(UP, up);
    _BOND_LINK(FAIL, fail);
    _BOND_LINK(DOWN, down);
    _BOND_LINK(BACK, back);
#undef _BOND_LINK
    return("UNKNOWN");
}
#endif
#endif
