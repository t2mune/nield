/*
 * ifamsg.c - interface address message parser
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

/*
 * parse interface address message
 */ 
int parse_ifamsg(struct nlmsghdr *nlh)
{
    struct ifaddrmsg *ifam;
    int ifam_len;
    struct rtattr *ifa[__IFA_MAX];
    char paddr[INET6_ADDRSTRLEN+1] = "";
    char laddr[INET6_ADDRSTRLEN+1] = "";
    char ifname[IFNAMSIZ] = "";
    char iflabel[IFNAMSIZ] = "";
    char msg[MAX_MSG_SIZE] = "";
    char *mp = msg;
    unsigned short iftype = -1;
    int log_opts = get_log_opts();
    int res;

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get ifaddrmsg */
    ifam_len = NLMSG_PAYLOAD(nlh, 0);
    if(ifam_len < sizeof(*ifam)) {
        rec_log("error: %s: ifaddrmsg: length too short", __func__);
        return(1);
    }
    ifam = (struct ifaddrmsg *)NLMSG_DATA(nlh);

    /* parse interface address attributes */
    parse_ifaddr(ifa, nlh);

    /* debug ifaddrmsg */
    if(log_opts & L_DEBUG)
        debug_ifamsg(0, ifam, ifa, ifam_len);

    /* check address family & set message type */
    if(ifam->ifa_family == AF_INET) {
        mp = add_log(msg, mp, "ipv4 ");
    } else if(ifam->ifa_family == AF_INET6) {
        mp = add_log(msg, mp, "ipv6 ");
    } else {
        rec_log("error: %s: unknown address family: %d",
            __func__, ifam->ifa_family);
        return(1);
    }

    /* get interface index & name */
    if_indextoname_from_lists(ifam->ifa_index, ifname);
    if(nlh->nlmsg_type == RTM_NEWADDR)
        mp = add_log(msg, mp, "address added: ");
    else if(nlh->nlmsg_type == RTM_DELADDR)
        mp = add_log(msg, mp, "address deleted: ");
    else {
        rec_log("error: %s: unknown nlmsg_type: %d",
            __func__, nlh->nlmsg_type);
        return(1);
    }

    /* get interface type */
    iftype = get_type_from_iflist(ifam->ifa_index);
    if(!iftype)
        iftype = get_type_from_ifhist(ifam->ifa_index);

    /* get prefix address */
    if(ifa[IFA_ADDRESS]) {
        res = inet_ntop_ifa(ifam->ifa_family, ifa[IFA_ADDRESS], paddr, sizeof(paddr));
        if(res) {
            rec_log("error: %s: IFA_ADDRESS(ifindex %d): %s",
                __func__, ifam->ifa_index,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
    }

    /* get local interface address */
    if(ifa[IFA_LOCAL]) {
        res = inet_ntop_ifa(ifam->ifa_family, ifa[IFA_LOCAL], laddr, sizeof(laddr));
        if(res) {
            rec_log("error: %s: IFA_LOCAL(ifindex %d): %s",
                __func__, ifam->ifa_index,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
    }

    /* whether interface type is P2P */
    if(ifa[IFA_LOCAL] && strcmp(laddr, paddr))
        mp = add_log(msg, mp, "interface=%s local=%s/%d peer=%s/%d ",
            ifname, laddr, ifam->ifa_prefixlen, paddr, ifam->ifa_prefixlen);
    else
        mp = add_log(msg, mp, "interface=%s ip=%s/%d ",
            ifname, paddr, ifam->ifa_prefixlen);

    /* get scope of address */
    mp = add_log(msg, mp, "socpe=%s ", conv_ifa_scope(ifam->ifa_scope, 0));

    /* get interface label */
    if(ifa[IFA_LABEL]) {
        if(RTA_PAYLOAD(ifa[IFA_LABEL]) > sizeof(iflabel)) {
            rec_log("error: %s: IFA_LABEL(ifindex %d): no payload",
                __func__, ifam->ifa_index);
            return(1);
        } else if(RTA_PAYLOAD(ifa[IFA_LABEL]) > sizeof(iflabel)) {
            rec_log("error: %s: IFA_LABEL(ifindex %d): payload too long",
                __func__, ifam->ifa_index);
            return(1);
        }
        memcpy(iflabel, RTA_DATA(ifa[IFA_LABEL]), IFNAMSIZ);
        if(strcmp(iflabel, ifname))
            mp = add_log(msg, mp, "label=%s ", iflabel);
    }

    if(ifa[IFA_CACHEINFO] && nlh->nlmsg_type == RTM_NEWADDR) {
        struct ifa_cacheinfo *ifac;

        if(RTA_PAYLOAD(ifa[IFA_CACHEINFO]) < sizeof(*ifac)) {
            rec_log("error: %s: IFA_CACHEINFO(ifindex %d): payload too short",
                __func__, ifam->ifa_index);
            return(1);
        }

        ifac = (struct ifa_cacheinfo *)RTA_DATA(ifa[IFA_CACHEINFO]);
        /* logging only when created not updated */
        if(ifac->cstamp != ifac->tstamp)
            return(1);
    }

    /* logging interface address message */
    rec_log("%s", msg);

    return(0);
}

/*
 * debug interface address message
 */ 
void debug_ifamsg(int lev, struct ifaddrmsg *ifam, struct rtattr *ifa[], int ifam_len)
{
    /* debug ifaddrmsg */
    char flags_list[MAX_STR_SIZE] = "";
    char ifname[IFNAMSIZ] = "";

    conv_ifa_flags(ifam->ifa_flags, flags_list, sizeof(flags_list));
    if_indextoname_from_lists(ifam->ifa_index, ifname);

    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ ifaddrmsg(%d) ]",
        NLMSG_ALIGN(sizeof(struct ifaddrmsg)));
    rec_dbg(lev, "    ifa_family(%d): %d(%s)",
        sizeof(ifam->ifa_family), ifam->ifa_family,
        conv_af_type(ifam->ifa_family, 1));
    rec_dbg(lev, "    ifa_prefixlen(%d): %d",
        sizeof(ifam->ifa_prefixlen), ifam->ifa_prefixlen);
    rec_dbg(lev, "    ifa_flags(%d): 0x%x(%s)",
        sizeof(ifam->ifa_flags), ifam->ifa_flags, flags_list);
    rec_dbg(lev, "    ifa_scope(%d): %d(%s)",
        sizeof(ifam->ifa_scope), ifam->ifa_scope,
        conv_ifa_scope(ifam->ifa_scope, 1));
    rec_dbg(lev, "    ifa_index(%d): %u(%s)",
        sizeof(ifam->ifa_index), ifam->ifa_index, ifname);

    /* debug interface address attributes */
    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ ifaddrmsg attributes(%d) ]",
        NLMSG_ALIGN(ifam_len - NLMSG_ALIGN(sizeof(struct ifaddrmsg))));

    if(ifa[IFA_ADDRESS])
        debug_rta_af(lev+1, ifa[IFA_ADDRESS],
            "IFA_ADDRESS", ifam->ifa_family);

    if(ifa[IFA_LOCAL])
        debug_rta_af(lev+1, ifa[IFA_LOCAL],
            "IFA_LOCAL", ifam->ifa_family);

    if(ifa[IFA_LABEL])
        debug_rta_str(lev+1, ifa[IFA_LABEL],
            "IFA_LABEL", NULL, IFNAMSIZ);

    if(ifa[IFA_BROADCAST])
        debug_rta_af(lev+1, ifa[IFA_BROADCAST],
            "IFA_BROADCAST", ifam->ifa_family);

    if(ifa[IFA_ANYCAST])
        debug_rta_af(lev+1, ifa[IFA_ANYCAST],
            "IFA_ANYCAST", ifam->ifa_family);

    if(ifa[IFA_CACHEINFO])
        debug_ifa_cacheinfo(lev+1, ifa[IFA_CACHEINFO],
            "IFA_CACHEINFO");

    if(ifa[IFA_MULTICAST])
        debug_rta_af(lev+1, ifa[IFA_MULTICAST],
            "IFA_MULTICAST", ifam->ifa_family);

    rec_dbg(lev, "");

    return;
}

/*
 * debug attribute IFA_CACHEINFO
 */
void debug_ifa_cacheinfo(int lev, struct rtattr *ifa, const char *name)
{
    struct ifa_cacheinfo *ifac;

    if(debug_rta_len_chk(lev, ifa, name, sizeof(*ifac)))
        return;

    ifac = (struct ifa_cacheinfo *)RTA_DATA(ifa);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(ifa->rta_len));
    rec_dbg(lev, "    [ ifa_cacheinfo(%d) ]",
        sizeof(struct ifa_cacheinfo));
    rec_dbg(lev, "        ifa_prefered(%d): 0x%x",
        sizeof(ifac->ifa_prefered), ifac->ifa_prefered);
    rec_dbg(lev, "        ifa_valid(%d): 0x%x",
        sizeof(ifac->ifa_valid), ifac->ifa_valid);
    rec_dbg(lev, "        cstamp(%d): %u",
        sizeof(ifac->cstamp), ifac->cstamp);
    rec_dbg(lev, "        tstamp(%d): %u",
        sizeof(ifac->tstamp), ifac->tstamp);
}

/*
 * convert interface address flags from number to string
 */
void conv_ifa_flags(int flags, char *flags_list, int len)
{
    if(!flags) {
        strncpy(flags_list, "NONE", len);
        return;
    }
#define _IFA_FLAGS(f) \
    if((flags & IFA_F_##f) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~IFA_F_##f) ? \
            strncat(flags_list, #f ",", len - strlen(flags_list) - 1) : \
            strncat(flags_list, #f, len - strlen(flags_list) - 1);
    _IFA_FLAGS(SECONDARY);
    _IFA_FLAGS(TEMPORARY);
#ifdef IFA_F_NODAD
    _IFA_FLAGS(NODAD);
#endif
    _IFA_FLAGS(OPTIMISTIC);
#ifdef IFA_F_DADFAILED
    _IFA_FLAGS(DADFAILED);
#endif
#ifdef IFA_F_HOMEADDRESS
    _IFA_FLAGS(HOMEADDRESS);
#endif
    _IFA_FLAGS(DEPRECATED);
    _IFA_FLAGS(TENTATIVE);
    _IFA_FLAGS(PERMANENT);
#undef _IFA_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, "UNKNOWN", len);
}

/*
 * convert interface address scope from number to string
 */
const char *conv_ifa_scope(int scope, unsigned char debug)
{
#define _IFA_SCOPE(s1, s2) \
    if(scope == RT_SCOPE_##s1) \
        return(debug ? #s1 : #s2);
    _IFA_SCOPE(UNIVERSE, global);
    _IFA_SCOPE(SITE, site);
    _IFA_SCOPE(LINK, link);
    _IFA_SCOPE(HOST, host);
    _IFA_SCOPE(NOWHERE, none);
#undef _IFA_SCOPE
    return(debug ? "UNKNOWN" : "unknown");
}
