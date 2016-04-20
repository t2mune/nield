/*
 * rtmsg.c - route message parser
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

/*
 * parse route message
 */
int parse_rtmsg(struct nlmsghdr *nlh)
{
    struct rtmsg *rtm;
    int rtm_len;
    struct rtattr *rta[__RTA_MAX];
    char ipv[MAX_STR_SIZE] = "";
    char msg[MAX_MSG_SIZE] = "";
    char *mp = msg;
    int log_opts = get_log_opts();
    int res;

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get rtmsg */
    rtm_len = NLMSG_PAYLOAD(nlh, 0);
    if(rtm_len < sizeof(*rtm)) {
        rec_log("error: %s: rtmsg: length too short", __func__);
        return(1);
    }
    rtm = (struct rtmsg *)NLMSG_DATA(nlh);

    /* parse route attributes */
    parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(nlh));

    /* debug rtmsg */
    if(log_opts & L_DEBUG)
        debug_rtmsg(0, rtm, rta, rtm_len);

    /* check address family */
    char dst[INET6_ADDRSTRLEN] = "";
    if(rtm->rtm_family == AF_INET) {
        strcpy(ipv, "ipv4");
        strcpy(dst, "0.0.0.0");
    } else if(rtm->rtm_family == AF_INET6) {
        strcpy(ipv, "ipv6");
        strcpy(dst, "::");
    } else {
        rec_log("error: %s: unknown address family: %d",
                __func__, rtm->rtm_family);
        return(1);
    }

    /* convert from table id to table name */
    char table[MAX_STR_SIZE] = "";
    snprintf(table, sizeof(table), "%s", conv_rt_table(rtm->rtm_table, 0));
    if(!strncmp(table, "unknown", sizeof(table)))
        snprintf(table, sizeof(table), "%d", rtm->rtm_table);

    /* check route table id(other than RT_TABLE_LOCAL) */
    if(rtm->rtm_table == RT_TABLE_LOCAL)
        return(1);

    /* check route protocol(other than RTPROT_UNSPEC) */
    if(rtm->rtm_protocol == RTPROT_UNSPEC)
        return(1);
    
    /* check route flags(other then RTM_F_CLONED) */
    if(rtm->rtm_flags & RTM_F_CLONED)
        return(1);

    /* get destination prefix */
    if(rta[RTA_DST]) {
        res = inet_ntop_ifa(rtm->rtm_family, rta[RTA_DST], dst, sizeof(dst));
        if(res) {
            rec_log("error: %s: RTA_DST: %s", __func__,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
    }
    /* no RTA_DST attribute if destination is a default gateway */
    mp = add_log(msg, mp, "destination=%s/%d ", dst, rtm->rtm_dst_len);

    /* get source prefix */
    if(rta[RTA_SRC]) {
        char src[INET6_ADDRSTRLEN] = "";

        res = inet_ntop_ifa(rtm->rtm_family, rta[RTA_SRC], src, sizeof(src));
        if(res == 1) {
            rec_log("error: %s: RTA_SRC: %s", __func__,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
        mp = add_log(msg, mp, "source=%s/%d ", src, rtm->rtm_src_len);
    }

    /* get preferred source address */
    if(rta[RTA_PREFSRC]) {
        char prefsrc[INET6_ADDRSTRLEN] = "";

        res = inet_ntop_ifa(rtm->rtm_family, rta[RTA_PREFSRC], prefsrc, sizeof(prefsrc));
        if(res) {
            rec_log("error: %s: RTA_PREFSRC: %s", __func__,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
        mp = add_log(msg, mp, "preferred-source=%s ", prefsrc);
    }

    /* get tos */
    if(rtm->rtm_tos)
        mp = add_log(msg, mp, "tos=0x%.2x ", rtm->rtm_tos);

    /* get ingress interface */
    if(rta[RTA_IIF]) {
        unsigned iifindex;
        char iifname[IFNAMSIZ] = "";

        if(RTA_PAYLOAD(rta[RTA_IIF]) < sizeof(iifindex)) {
            rec_log("error: %s: RTA_IIF: payload too short", __func__);
            return(1);
        }
        iifindex = *((unsigned *)RTA_DATA(rta[RTA_IIF]));
        if_indextoname_from_lists(iifindex, iifname);

        mp = add_log(msg, mp, "in=%s ", iifname);
    }

    /* get gateway address */
    if(rta[RTA_GATEWAY]) {
        char nexthop[INET6_ADDRSTRLEN] = "";

        res = inet_ntop_ifa(rtm->rtm_family, rta[RTA_GATEWAY], nexthop, sizeof(nexthop));
        if(res) {
            rec_log("error: %s: RTA_GATEWAY: %s", __func__,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
        mp = add_log(msg, mp, "nexthop=%s ", nexthop);
    }

    /* get egress interface */
    if(rta[RTA_OIF]) {
        unsigned oifindex;
        char oifname[IFNAMSIZ] = "";

        if(RTA_PAYLOAD(rta[RTA_OIF]) < sizeof(oifindex)) {
            rec_log("error: %s: RTA_OIF: payload too short", __func__);
            return(1);
        }
        oifindex = *((unsigned *)RTA_DATA(rta[RTA_OIF]));
        if_indextoname_from_lists(oifindex, oifname);

        mp = add_log(msg, mp, "interface=%s ", oifname);
    }

    /* get priority(but metric) */
    char metric[MAX_STR_SIZE] = "";
    if(rta[RTA_PRIORITY]) {
        if(RTA_PAYLOAD(rta[RTA_PRIORITY]) < sizeof(int)) {
            rec_log("error: %s: RTA_PRIORITY: payload too short", __func__);
            return(1);
        }
        snprintf(metric, sizeof(metric), "metric=%d ", *((int *)RTA_DATA(rta[RTA_PRIORITY])));
    }

    /* convert route message type */
    char type[MAX_STR_SIZE] = "";
    snprintf(type, sizeof(type), "%s", conv_rtn_type(rtm->rtm_type, 0));

    /* convert route message protocol */
    char proto[MAX_STR_SIZE] = "";
    snprintf(proto, sizeof(proto), "%s", conv_rtprot(rtm->rtm_protocol, 0));

    /* get table id & name */
    if(rta[RTA_TABLE]) {
        int table_id = *(int *)RTA_DATA(rta[RTA_TABLE]);

        if(RTA_PAYLOAD(rta[RTA_TABLE]) < sizeof(int)) {
            rec_log("error: %s: RTA_TABLE: payload too short", __func__);
            return(1);
        }
        snprintf(table, sizeof(table), "%s", conv_rt_table(table_id, 0));
        if(!strncmp(table, "unknown", sizeof(table)))
            snprintf(table, sizeof(table), "%d", table_id);
    }

    /* get multipath */
    if(rta[RTA_MULTIPATH]) {
        struct rtnexthop *rtnh;
        int rtnh_len = RTA_PAYLOAD(rta[RTA_MULTIPATH]);
        struct rtattr *rtna[__RTA_MAX];
        char rtnh_ifname[IFNAMSIZ] = "";
        char rtnh_nexthop[INET6_ADDRSTRLEN] = "";

        if(RTA_PAYLOAD(rta[RTA_MULTIPATH]) < sizeof(*rtnh)) {
            rec_log("error: %s: RTA_MULTIPATH: payload too short", __func__);
            return(1);
        }
        rtnh = RTA_DATA(rta[RTA_MULTIPATH]);

        for(; RTNH_OK(rtnh, rtnh_len);
            rtnh = RTNH_NEXT(rtnh), rtnh_len -= RTNH_ALIGN(rtnh->rtnh_len)) {
            parse_rtattr(rtna, RTA_MAX, RTNH_DATA(rtnh), rtnh->rtnh_len - sizeof(*rtnh));

            if(rtna[RTA_GATEWAY]) {
                res = inet_ntop_ifa(rtm->rtm_family, rtna[RTA_GATEWAY],
                    rtnh_nexthop, sizeof(rtnh_nexthop));
                if(res) {
                    rec_log("error: %s: RTA_GATEWAY: %s", __func__,
                        (res == 1) ? strerror(errno) : "payload too short");
                    return(1);
                }
            }

            /* get interface name & logging routing table message */
            if_indextoname_from_lists(rtnh->rtnh_ifindex, rtnh_ifname);
            if(nlh->nlmsg_type == RTM_NEWROUTE)
                rec_log("%s route added: %snexthop=%s interface=%s "
                    "%sweight=%d type=%s protocol=%s table=%s",
                    ipv, msg, rtnh_nexthop, rtnh_ifname,
                    metric, rtnh->rtnh_hops+1, type, proto, table);
            else if(nlh->nlmsg_type == RTM_DELROUTE)
                rec_log("%s route deleted: %snexthop=%s interface=%s " 
                    "%sweight=%d type=%s protocol=%s table=%s",
                    ipv, msg, rtnh_nexthop, rtnh_ifname,
                    metric, rtnh->rtnh_hops+1, type, proto, table);
        }

        return(0);
    }

    /* logging routing message */
    if(nlh->nlmsg_type == RTM_NEWROUTE)
        rec_log("%s route added: %s%stype=%s protocol=%s table=%s",
            ipv, msg, metric, type, proto, table);
    else if(nlh->nlmsg_type == RTM_DELROUTE)
        rec_log("%s route deleted: %s%stype=%s proto=%s table=%s",
            ipv, msg, metric, type, proto, table);

    return(0);
}

/*
 * debug route message
 */
void debug_rtmsg(int lev, struct rtmsg *rtm, struct rtattr *rta[], int rtm_len)
{
    /* debug rtmsg */
    char flags_list[MAX_STR_SIZE] = "";

    conv_rtm_flags(rtm->rtm_flags, flags_list, sizeof(flags_list));

    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ rtmsg(%d) ]",
        NLMSG_ALIGN(sizeof(struct rtmsg)));
    rec_dbg(lev, "    rtm_family(%d): %d(%s)",
        sizeof(rtm->rtm_family), rtm->rtm_family,
        conv_af_type(rtm->rtm_family, 1));
    rec_dbg(lev, "    rtm_dst_len(%d): %d",
        sizeof(rtm->rtm_dst_len), rtm->rtm_dst_len);
    rec_dbg(lev, "    rtm_src_len(%d): %d",
        sizeof(rtm->rtm_src_len), rtm->rtm_src_len);
    rec_dbg(lev, "    rtm_tos(%d): %d",
        sizeof(rtm->rtm_tos), rtm->rtm_tos);
    rec_dbg(lev, "    rtm_table(%d): %d(%s)",
        sizeof(rtm->rtm_table), rtm->rtm_table,
        conv_rt_table(rtm->rtm_table, 1));
    rec_dbg(lev, "    rtm_protocol(%d): %d(%s)",
        sizeof(rtm->rtm_protocol), rtm->rtm_protocol,
        conv_rtprot(rtm->rtm_protocol, 1));
    rec_dbg(lev, "    rtm_scope(%d): %d(%s)",
        sizeof(rtm->rtm_scope), rtm->rtm_scope,
        conv_rt_scope(rtm->rtm_scope));
    rec_dbg(lev, "    rtm_type(%d): %d(%s)",
        sizeof(rtm->rtm_type), rtm->rtm_type,
        conv_rtn_type(rtm->rtm_type, 1));
    rec_dbg(lev, "    rtm_flags(%d): %d(%s)",
        sizeof(rtm->rtm_flags), rtm->rtm_flags, flags_list);

    /* debug route attributes */
    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ rtmsg attributes(%d) ]",
        NLMSG_ALIGN(rtm_len - NLMSG_ALIGN(sizeof(struct rtmsg))));

    if(rta[RTA_DST])
        debug_rta_af(lev+1, rta[RTA_DST],
            "RTA_DST", rtm->rtm_family);

    if(rta[RTA_SRC])
        debug_rta_af(lev+1, rta[RTA_SRC],
            "RTA_SRC", rtm->rtm_family);

    if(rta[RTA_IIF])
        debug_rta_ifindex(lev+1, rta[RTA_IIF],
            "RTA_IIF");

    if(rta[RTA_OIF])
        debug_rta_ifindex(lev+1, rta[RTA_OIF],
            "RTA_OIF");

    if(rta[RTA_GATEWAY])
        debug_rta_af(lev+1, rta[RTA_GATEWAY],
            "RTA_GATEWAY", rtm->rtm_family);

    if(rta[RTA_PRIORITY])
        debug_rta_s32(lev+1, rta[RTA_PRIORITY],
            "RTA_PRIORITY", NULL);

    if(rta[RTA_PREFSRC])
        debug_rta_af(lev+1, rta[RTA_PREFSRC],
            "RTA_PREFSRC", rtm->rtm_family);

    if(rta[RTA_METRICS])
        debug_rta_metrics(lev+1, rta[RTA_METRICS],
            "RTA_METRICS");

    if(rta[RTA_MULTIPATH])
        debug_rta_multipath(lev+1, rtm, rta[RTA_MULTIPATH],
            "RTA_MULTIPATH");

    if(rta[RTA_FLOW])
        debug_rta_u32(lev+1, rta[RTA_FLOW],
            "RTA_FLOW", NULL);

    if(rta[RTA_CACHEINFO])
        debug_rta_cacheinfo(lev+1, rta[RTA_CACHEINFO],
            "RTA_CACHEINFO");

    if(rta[RTA_TABLE])
        debug_rta_s32(lev+1, rta[RTA_TABLE],
            "RTA_TABLE", conv_rt_table);

#if HAVE_DECL_RTA_MARK
    if(rta[RTA_MARK])
        debug_rta_u32(lev+1, rta[RTA_MARK],
            "RTA_MARK", NULL);
#endif

    rec_dbg(lev, "");

    return;
}

/*
 * debug attribute RTA_METRICS
 */
void debug_rta_metrics(int lev, struct rtattr *rta, const char *name)
{
    struct rtattr *rtax[RTAX_MAX+1];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(rta->rta_len));
    parse_rtattr(rtax, RTAX_MAX, RTA_DATA(rta), RTA_PAYLOAD(rta));

    if(rtax[RTAX_LOCK])
        debug_rta_u32(lev+1, rtax[RTAX_LOCK],
            "RTAX_LOCK", NULL);

    if(rtax[RTAX_MTU])
        debug_rta_u32(lev+1, rtax[RTAX_MTU],
            "RTAX_MTU", NULL);

    if(rtax[RTAX_ADVMSS])
        debug_rta_u32(lev+1, rtax[RTAX_ADVMSS],
            "RTAX_ADVMSS", NULL);

    if(rtax[RTAX_HOPLIMIT])
        debug_rta_s32(lev+1, rtax[RTAX_HOPLIMIT],
            "RTAX_HOPLIMIT", NULL);

    if(rtax[RTAX_WINDOW])
        debug_rta_u32(lev+1, rtax[RTAX_WINDOW],
            "RTAX_WINDOW", NULL);
}

/*
 * debug attribute RTA_MULTIPATH
 */
void debug_rta_multipath(int lev, struct rtmsg *rtm, struct rtattr *rta, const char *name)
{
    struct rtnexthop *rtnh;
    int rtnh_len = RTA_PAYLOAD(rta);
    struct rtattr *rtnha[__RTA_MAX];
    char ifname[IFNAMSIZ] = "";
    char flags_list[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, rta, name, sizeof(*rtnh)))
        return;

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(rta->rta_len));

    for(rtnh = RTA_DATA(rta); RTNH_OK(rtnh, rtnh_len);
        rtnh = RTNH_NEXT(rtnh), rtnh_len -= RTNH_ALIGN(rtnh->rtnh_len)) {
        conv_rtnh_flags(rtnh->rtnh_flags, flags_list, sizeof(flags_list));
        if_indextoname_from_lists(rtnh->rtnh_ifindex, ifname);

        rec_dbg(lev, "    [ rtnexthop(%d) ]", sizeof(*rtnh));
        rec_dbg(lev, "        rtnh_len(%d): %hu",
            sizeof(rtnh->rtnh_len), rtnh->rtnh_len);
        rec_dbg(lev, "        rtnh_flags(%d): %d(%s)",
            sizeof(rtnh->rtnh_flags), rtnh->rtnh_flags, flags_list);
        rec_dbg(lev, "        rtnh_hops(%d): %d",
            sizeof(rtnh->rtnh_hops), rtnh->rtnh_hops);
        rec_dbg(lev, "        rtnh_ifindex(%d): %d(%s)",
            sizeof(rtnh->rtnh_ifindex), rtnh->rtnh_ifindex, ifname);

        parse_rtattr(rtnha, RTA_MAX, RTNH_DATA(rtnh), rtnh->rtnh_len - sizeof(*rtnh));

        if(rtnha[RTA_GATEWAY])
            debug_rta_af(lev+3, rtnha[RTA_GATEWAY], "RTA_GATEWAY", rtm->rtm_family);
    }
}

/*
 * debug attribute RTA_CACHEINFO
 */
void debug_rta_cacheinfo(int lev, struct rtattr *rta, const char *name)
{
    struct rta_cacheinfo *rtac;

    if(debug_rta_len_chk(lev, rta, name, sizeof(*rtac)))
        return;

    rtac = (struct rta_cacheinfo *)RTA_DATA(rta);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(rta->rta_len));
    rec_dbg(lev, "    [ rta_cacheinfo(%d) ]", sizeof(*rtac));
    rec_dbg(lev, "        rta_clntref(%d): %u",
        sizeof(rtac->rta_clntref), rtac->rta_clntref);
    rec_dbg(lev, "        rta_lastuse(%d): %u",
        sizeof(rtac->rta_lastuse), rtac->rta_lastuse);
    rec_dbg(lev, "        rta_expires(%d): %d",
        sizeof(rtac->rta_expires), rtac->rta_expires);
    rec_dbg(lev, "        rta_error(%d): %u",
        sizeof(rtac->rta_error), rtac->rta_error);
    rec_dbg(lev, "        rta_used(%d): %u",
        sizeof(rtac->rta_used), rtac->rta_used);
    rec_dbg(lev, "        rta_id(%d): %u",
        sizeof(rtac->rta_id), rtac->rta_id);
    rec_dbg(lev, "        rta_ts(%d): %u",
        sizeof(rtac->rta_ts), rtac->rta_ts);
    rec_dbg(lev, "        rta_tsage(%d): %u",
        sizeof(rtac->rta_tsage), rtac->rta_tsage);
}

/*
 * convert rtm_table from number to string
 */
const char *conv_rt_table(int table, unsigned char debug)
{
#define _RT_TABLE(s1, s2) \
    if(table == RT_TABLE_##s1) \
        return(debug ? #s1 : #s2);
    _RT_TABLE(UNSPEC, none);
#if HAVE_DECL_RT_TABLE_COMPAT
    _RT_TABLE(COMPAT, compat);
#endif
    _RT_TABLE(DEFAULT, default);
    _RT_TABLE(MAIN, main);
    _RT_TABLE(LOCAL, local);
#undef _RT_TABLE
    return(debug ? "UNKNOWN" : "unknown");
}

/*
 * convert rtm_protocol from number to string
 */
const char *conv_rtprot(int protocol, unsigned char debug)
{
#define _RTM_PROTOCOL(s1, s2) \
    if(protocol == RTPROT_##s1) \
        return(debug ? #s1: #s2);
    _RTM_PROTOCOL(UNSPEC, none);
    _RTM_PROTOCOL(REDIRECT, redirect);
    _RTM_PROTOCOL(KERNEL, kernel);
    _RTM_PROTOCOL(BOOT, boot);
    _RTM_PROTOCOL(STATIC, static);
    _RTM_PROTOCOL(GATED, gated);
    _RTM_PROTOCOL(RA, ra);
    _RTM_PROTOCOL(MRT, ra);
    _RTM_PROTOCOL(ZEBRA, zebra);
    _RTM_PROTOCOL(BIRD, bird);
    _RTM_PROTOCOL(DNROUTED, dnrouted);
    _RTM_PROTOCOL(XORP, xorp);
    _RTM_PROTOCOL(NTK, ntk);
#if HAVE_DECL_RTPROT_DHCP
    _RTM_PROTOCOL(DHCP, dhcp);
#endif
#undef _RTM_PROTOCOL
    return(debug ? "UNKNOWN" : "unknown");
}

/*
 * convert rtm_scope from number to string
 */
const char *conv_rt_scope(int scope)
{
#define _RT_SCOPE(s) \
    if(scope == RT_SCOPE_##s) \
        return(#s);
    _RT_SCOPE(UNIVERSE);
    _RT_SCOPE(SITE);
    _RT_SCOPE(LINK);
    _RT_SCOPE(HOST);
    _RT_SCOPE(NOWHERE);
#undef _RT_SCOPE
    return("UNKNOWN");
}

/*
 * convert rtm_type from number to string
 */
const char *conv_rtn_type(int type, unsigned char debug)
{
#define _RTN_TYPE(s1, s2) \
    if(type == RTN_##s1) \
        return(debug ? #s1 : #s2);
    _RTN_TYPE(UNSPEC, none);
    _RTN_TYPE(UNICAST, unicast);
    _RTN_TYPE(LOCAL, local);
    _RTN_TYPE(BROADCAST, broadcast);
    _RTN_TYPE(ANYCAST, anycast);
    _RTN_TYPE(MULTICAST, multicast);
    _RTN_TYPE(BLACKHOLE, blackhole);
    _RTN_TYPE(UNREACHABLE, unreachable);
    _RTN_TYPE(PROHIBIT, prohibit);
    _RTN_TYPE(THROW, throw);
    _RTN_TYPE(NAT, nat);
    _RTN_TYPE(XRESOLVE, external);
#undef _RTN_TYPE
    return(debug ? "UNKNOWN" : "unknown");
}

/*
 * convert rtm_flags from number to string
 */
void conv_rtm_flags(int flags, char *flags_list, int len)
{
    if(!flags) {
        strncpy(flags_list, "NONE", len);
        return;
    }
#define _RTM_FLAGS(s) \
    if((flags & RTM_F_##s) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~RTM_F_##s) ? \
            strncat(flags_list, #s ", ", len - strlen(flags_list) - 1) : \
            strncat(flags_list, #s, len - strlen(flags_list) - 1);
    _RTM_FLAGS(NOTIFY);
    _RTM_FLAGS(CLONED);
    _RTM_FLAGS(EQUALIZE);
    _RTM_FLAGS(PREFIX);
#undef _RTM_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, "UNKNOWN", len);
}

/*
 * convert rtnh_flags from number to string
 */
void conv_rtnh_flags(int flags, char *flags_list, int len)
{
    if(!flags) {
        strncpy(flags_list, "NONE", len);
        return;
    }
#define _RTNH_FLAGS(s) \
    if((flags & RTNH_F_##s) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~RTNH_F_##s) ? \
            strncat(flags_list, #s ", ", len - strlen(flags_list) - 1) : \
            strncat(flags_list, #s, len - strlen(flags_list) - 1);
    _RTNH_FLAGS(DEAD);
    _RTNH_FLAGS(PERVASIVE);
    _RTNH_FLAGS(ONLINK);
#undef _RTNH_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, "UNKNOWN", len);
}
