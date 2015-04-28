/*
 * frhdr.c - fib rule message parser
 * Copyright (C) 2015 Tetsumune KISO <t2mune@gmail.com>
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

#ifdef HAVE_LINUX_FIB_RULES_H
/*
 * parse fib rule message
 */
int parse_frhdr(struct nlmsghdr *nlh)
{
    struct fib_rule_hdr *frh;
    int frh_len;
    struct rtattr *fra[__FRA_MAX];
    char msg[148] = "", action[16] = "";
    char *mp = msg;
    int log_opts = get_log_opts();
    int res;

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get fib rule header */
    frh_len = NLMSG_PAYLOAD(nlh, 0);
    if(frh_len < sizeof(*frh)) {
        rec_log("error: %s: fib_rule_hdr: length too short", __func__);
        return(1);
    }
    frh = (struct fib_rule_hdr *)NLMSG_DATA(nlh);

    /* parse fib rule attributes */
    parse_frule(fra, nlh);

    /* debug fib_rule_hdr */
    if(log_opts & L_DEBUG)
        debug_frhdr(0, frh, fra, frh_len);

    /* check address family */
    if(frh->family == AF_INET)
        mp = add_log(msg, mp, "ipv4 ");
    else if(frh->family == AF_INET6)
        mp = add_log(msg, mp, "ipv6 ");
    else {
        rec_log("error: %s: unknown address family: %d",
            __func__, frh->family);
        return(1);
    }

    /* check message type */
    if(nlh->nlmsg_type == RTM_NEWRULE)
        mp = add_log(msg, mp, "rule added: ");
    else if(nlh->nlmsg_type == RTM_DELRULE)
        mp = add_log(msg, mp, "rule deleted: ");
    else {
        rec_log("error: %s: unknown netlink message type: %d",
            __func__, nlh->nlmsg_type);
        return(1);
    }

    /* check route table id(other than local) */
    if(frh->table == RT_TABLE_LOCAL)
        return(1);

    /* check whether invert rule or not */
    if(frh->flags & FIB_RULE_INVERT)
        mp = add_log(msg, mp, "not ");

        /* get source prefix */
    if(fra[FRA_SRC]) {
        char src[INET6_ADDRSTRLEN] = "";

        res = inet_ntop_ifa(frh->family, fra[FRA_SRC], src, sizeof(src));
        if(res) {
            rec_log("error: %s: FRA_SRC: %s", __func__,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
        mp = add_log(msg, mp, "from=%s/%d ", src, frh->src_len);
    } 

    /* get egress interface index & name */
    if(fra[FRA_IFNAME]) {
        char ifname[IFNAMSIZ]; 

        if(!RTA_PAYLOAD(fra[FRA_IFNAME])) {
            rec_log("error: %s: FRA_IFNAME: no payload", __func__);
            return(1);
        } else if(RTA_PAYLOAD(fra[FRA_IFNAME]) > sizeof(ifname)) {
            rec_log("error: %s: FRA_IFNAME: payload too long", __func__);
            return(1);
        }
        memcpy(ifname, RTA_DATA(fra[FRA_IFNAME]), sizeof(ifname));
#ifdef FIB_RULE_IIF_DETACHED
        if(frh->flags & FIB_RULE_IIF_DETACHED) {
            mp = add_log(msg, mp, "in=%s(detached) ", ifname);
            return(0);
        }
#endif
        mp = add_log(msg, mp, "in=%s ", ifname);
    }

    /* get tos value */
    if(frh->tos)
        mp = add_log(msg, mp, "tos=0x%.2x ", frh->tos);

        /* get destination prefix */
    if(fra[FRA_DST]) {
        char dst[INET6_ADDRSTRLEN] = "";

        res = inet_ntop_ifa(frh->family, fra[FRA_DST], dst, sizeof(dst));
        if(res) {
            rec_log("error: %s: FRA_DST: %s", __func__,
                (res == 1) ? strerror(errno) : "payload too short");
            return(1);
        }
        mp = add_log(msg, mp, "to=%s/%d ", dst, frh->dst_len);
    }

#if HAVE_DECL_FRA_OIFNAME
    /* get egress interface index & name */
    if(fra[FRA_OIFNAME]) {
        char oifname[IFNAMSIZ]; 

        if(!RTA_PAYLOAD(fra[FRA_OIFNAME])) {
            rec_log("error: %s: FRA_OIFNAME: no payload", __func__);
            return(1);
        } else if(RTA_PAYLOAD(fra[FRA_OIFNAME]) > sizeof(oifname)) {
            rec_log("error: %s: FRA_OIFNAME: payload too long", __func__);
            return(1);
        }
        memcpy(oifname, RTA_DATA(fra[FRA_OIFNAME]), sizeof(oifname));
#ifdef FIB_RULE_OIF_DETACHED
        if(frh->flags & FIB_RULE_OIF_DETACHED) {
            mp = add_log(msg, mp, "out=%s(detached) ", oifname);
            return(0);
        }
#endif
        mp = add_log(msg, mp, "out=%s ", oifname);
    }
#endif

    /* get fwmark */
    unsigned fwmark = 0;
    if(fra[FRA_FWMARK]) {
        if(RTA_PAYLOAD(fra[FRA_FWMARK]) < sizeof(fwmark)) {
            rec_log("error: %s: FRA_FWMARK: payload too short", __func__);
            return(1);
        }
        fwmark = *(unsigned *)RTA_DATA(fra[FRA_FWMARK]);
    }

    /* get fwmask */
    unsigned fwmask = 0;
    if(fra[FRA_FWMASK]) {
        if(RTA_PAYLOAD(fra[FRA_FWMASK]) < sizeof(fwmask)) {
            rec_log("error: %s: FRA_FWMASK: payload too short", __func__);
            return(1);
        }
        fwmask = *(unsigned *)RTA_DATA(fra[FRA_FWMASK]);
    }

    if(fwmark || fwmask) {
        if(fwmask != 0xFFFFFFFF)
            mp = add_log(msg, mp, "fwmark=0x%x/0x%x ", fwmark, fwmask);
        else
            mp = add_log(msg, mp, "fwmark=0x%x ", fwmark);
    }

    /* get source and destination realms */
    if(fra[FRA_FLOW]) {
        unsigned srcrlm;
        unsigned dstrlm;

        if(RTA_PAYLOAD(fra[FRA_FLOW]) < sizeof(srcrlm)) {
            rec_log("error: %s: FRA_FLOW: payload too short", __func__);
            return(1);
        }
        srcrlm = *(unsigned *)RTA_DATA(fra[FRA_FLOW]);
        srcrlm &= 0xFFFF;
        if(srcrlm)
            mp = add_log(msg, mp, "source-realm=%u ", srcrlm);
        dstrlm = srcrlm >> 16;
        mp = add_log(msg, mp, "destination-realm=%u ", dstrlm);
    }

#if HAVE_DECL_FRA_GOTO
    /* get another rule to junmp to */
    if(fra[FRA_GOTO]) {
        if(RTA_PAYLOAD(fra[FRA_GOTO]) < sizeof(unsigned)) {
            rec_log("error: %s: FRA_GOTO: payload too short", __func__);
            return(1);
        }
        mp = add_log(msg, mp, "goto=%u ", *(unsigned *)RTA_DATA(fra[FRA_GOTO]));
    }
#endif

    /* convert route table name */
    if(fra[FRA_TABLE]) {
        unsigned table_id = *(unsigned *)RTA_DATA(fra[FRA_TABLE]);
        char table[16] = "";

        if(RTA_PAYLOAD(fra[FRA_TABLE]) < sizeof(unsigned)) {
            rec_log("error: %s: FRA_TABLE: payload too short", __func__);
            return(1);
        }
        snprintf(table, sizeof(table), "%s", conv_rt_table(table_id, 0));
        if(!strncmp(table, "unknown", sizeof(table)))
            mp = add_log(msg, mp, "table=%u ", table_id);
        else
            mp = add_log(msg, mp, "table=%s ", table);
    }

    /* get fib rule priority */
    if(fra[FRA_PRIORITY]) {
        if(RTA_PAYLOAD(fra[FRA_PRIORITY]) < sizeof(unsigned)) {
            rec_log("error: %s: FRA_PRIORITY: payload too short", __func__);
            return(1);
        }
        mp = add_log(msg, mp, "priority=%u ", *(unsigned *)RTA_DATA(fra[FRA_PRIORITY]));
    }

    /* convert fib rule action */
    snprintf(action, sizeof(action), "%s", conv_fr_act(frh->action, 0));

    /* logging fib rule */
    if(frh->flags & FIB_RULE_UNRESOLVED)
        rec_log("%saction=%s(unresolved)", msg, action);
    else
        rec_log("%saction=%s", msg, action);

    return(0);
}

/*
 * debugging fib rule message
 */
void debug_frhdr(int lev, struct fib_rule_hdr *frh, struct rtattr *fra[], int frh_len)
{
    char flags_list[MAX_STR_SIZE] = "";

    conv_fib_rule_flags(frh->flags, flags_list, sizeof(flags_list));

    /* debug frhdr */
    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ fib_rule_hdr(%d) ]",
        NLMSG_ALIGN(sizeof(struct fib_rule_hdr)));
    rec_dbg(lev, "    family(%d): %d(%s)",
        sizeof(frh->family), frh->family,
        conv_af_type(frh->family, 1));
    rec_dbg(lev, "    dst_len(%d): %d",
        sizeof(frh->dst_len), frh->dst_len);
    rec_dbg(lev, "    src_len(%d): %d",
        sizeof(frh->src_len), frh->src_len);
    rec_dbg(lev, "    tos(%d): 0x%.2x",
        sizeof(frh->tos), frh->tos);
    rec_dbg(lev, "    table(%d): %d",
        sizeof(frh->table), frh->table);
    rec_dbg(lev, "    res1(%d): %d",
        sizeof(frh->res1), frh->res1);
    rec_dbg(lev, "    res2(%d): %d",
        sizeof(frh->res2), frh->res2);
    rec_dbg(lev, "    action(%d): %d(%s)",
        sizeof(frh->action), frh->action,
        conv_fr_act(frh->action, 1));
    rec_dbg(lev, "    flags(%d): %u(%s)",
        sizeof(frh->flags), frh->flags, flags_list);

    /* debug fib rule attributes */
    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ fib_rule_hdr attributes(%d) ]",
        NLMSG_ALIGN(frh_len - NLMSG_ALIGN(sizeof(struct fib_rule_hdr))));

    if(fra[FRA_DST])
        debug_rta_af(lev+1, fra[FRA_DST],
            "FRA_DST", frh->family);

    if(fra[FRA_SRC])
        debug_rta_af(lev+1, fra[FRA_SRC],
            "FRA_SRC", frh->family);

    if(fra[FRA_IFNAME])
        debug_rta_str(lev+1, fra[FRA_IFNAME],
            "FRA_IFNAME", NULL, IFNAMSIZ);

#if HAVE_DECL_FRA_GOTO
    if(fra[FRA_GOTO])
        debug_rta_u32(lev+1, fra[FRA_GOTO],
            "FRA_GOTO", NULL);
#endif

    if(fra[FRA_PRIORITY])
        debug_rta_u32(lev+1, fra[FRA_PRIORITY],
            "FRA_PRIORITY", NULL);

    if(fra[FRA_FWMARK])
        debug_rta_u32(lev+1, fra[FRA_FWMARK],
            "FRA_FWMARK", NULL);

    if(fra[FRA_FLOW])
        debug_rta_u32x(lev+1, fra[FRA_FLOW],
            "FRA_FLOW", NULL);

    if(fra[FRA_TABLE])
        debug_rta_s32(lev+1, fra[FRA_TABLE],
            "FRA_TABLE", conv_rt_table);

    if(fra[FRA_FWMASK])
        debug_rta_u32(lev+1, fra[FRA_FWMASK],
            "FRA_FWMASK", NULL);

#if HAVE_DECL_FRA_OIFNAME
    if(fra[FRA_OIFNAME])
        debug_rta_str(lev+1, fra[FRA_OIFNAME],
            "FRA_OIFNAME", NULL, IFNAMSIZ);
#endif

    rec_dbg(lev, "");
}

/*
 * convert frh->action from number to string
 */
const char *conv_fr_act(int action, unsigned char debug)
{
#define _FR_ACT(s1, s2) \
    if(action == FR_ACT_##s1) \
        return(debug ? #s1 : #s2);
    _FR_ACT(UNSPEC, none);
    _FR_ACT(TO_TBL, to_tbl);
#if HAVE_DECL_FR_ACT_GOTO
    _FR_ACT(GOTO, goto);
#endif
#if HAVE_DECL_FR_ACT_NOP
    _FR_ACT(NOP, nop);
#endif
#if HAVE_DECL_FR_ACT_RES1
    _FR_ACT(RES1, res1);
#endif
#if HAVE_DECL_FR_ACT_RES2
    _FR_ACT(RES2, res2);
#endif
    _FR_ACT(RES3, res3);
    _FR_ACT(RES4, res4);
    _FR_ACT(BLACKHOLE, blackhole);
    _FR_ACT(UNREACHABLE, unreachable);
    _FR_ACT(PROHIBIT, prohibit);
#undef _FR_ACT
    return(debug ? "UNKNOWN" : "unknown");
}

/*
 * convert frh->flags from number to string
 */
void conv_fib_rule_flags(int flags, char *flags_list, int len)
{
    if(!flags) {
        strncpy(flags_list, "NONE", len);
        return;
    }
#define _FIB_RULE_FLAGS(s) \
    if((flags & FIB_RULE_##s) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~FIB_RULE_##s) ? \
            strncat(flags_list, #s ",", len - strlen(flags_list) - 1) : \
            strncat(flags_list, #s, len - strlen(flags_list) - 1); 
    _FIB_RULE_FLAGS(PERMANENT);
#ifdef FIB_RULE_INVERT
    _FIB_RULE_FLAGS(INVERT);
#endif
#ifdef FIB_RULE_UNRESOLVED
    _FIB_RULE_FLAGS(UNRESOLVED);
#endif
#ifdef FIB_RULE_IIF_DETACHED
    _FIB_RULE_FLAGS(IIF_DETACHED);
#endif
#ifdef FIB_RULE_OIF_DETACHED
    _FIB_RULE_FLAGS(OIF_DETACHED);
#endif
#undef _FIB_RULE_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, "UNKNOWN", len);
}
#endif
