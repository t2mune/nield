/*
 * tcamsg_csum.c - traffic control message parser
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

#ifdef HAVE_LINUX_TC_ACT_TC_CSUM_H
/*
 * parse csum options(TCA_ACT_CSUM: 16)
 */
int parse_tca_act_options_csum(char *msg, char *mp, struct rtattr *act)
{
    struct rtattr *csum[__TCA_CSUM_MAX];

    parse_nested_rtattr(csum, TCA_CSUM_MAX, act);

    if(csum[TCA_CSUM_PARMS]) {
        struct tc_csum *parms;
        char flags_list[MAX_STR_SIZE] = "";

        if(RTA_PAYLOAD(csum[TCA_CSUM_PARMS]) < sizeof(*parms)) {
            rec_log("error: %s: payload too short", __func__);
            return(1);
        }
        parms = (struct tc_csum *)RTA_DATA(csum[TCA_CSUM_PARMS]);
        conv_tca_csum_update_flags(parms->update_flags,
            flags_list, sizeof(flags_list), 0);
    
        mp = add_log(msg, mp, "index=%d protocol=%s next=%s ",
            parms->index, flags_list,
            conv_tc_action(parms->action, 0));
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * debug csum options(TCA_ACT_CSUM: 16)
 */
void debug_tca_act_options_csum(int lev, struct rtattr *act)
{
    struct rtattr *csum[__TCA_CSUM_MAX];

    parse_nested_rtattr(csum, TCA_CSUM_MAX, act);

    if(csum[TCA_CSUM_TM])
        debug_tca_csum_tm(lev+1, csum[TCA_CSUM_TM],
            "TCA_CSUM_TM");

    if(csum[TCA_CSUM_PARMS])
        debug_tca_csum_parms(lev+1, csum[TCA_CSUM_PARMS],
            "TCA_CSUM_PARMS");
}

/*
 * debug attribute TCA_CSUM_TM
 */
void debug_tca_csum_tm(int lev, struct rtattr *csum, const char *name)
{
    struct tcf_t *tm;

    if(debug_rta_len_chk(lev, csum, name, sizeof(*tm)))
        return;

    tm = (struct tcf_t *)RTA_DATA(csum);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(csum->rta_len));
    debug_tcf_t(lev+1, tm);
}

/*
 * debug attribute TCA_CSUM_PARMS
 */
void debug_tca_csum_parms(int lev, struct rtattr *csum, const char *name)
{
    struct tc_csum *parms;
    char flags_list[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, csum, name, sizeof(*parms)))
        return;

    parms = (struct tc_csum *)RTA_DATA(csum);
    conv_tca_csum_update_flags(parms->update_flags, flags_list, sizeof(flags_list), 1);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(csum->rta_len));
    rec_dbg(lev, "    [ tc_csum(%d) ]", sizeof(*parms));
    rec_dbg(lev, "        index(%d): 0x%08x", sizeof(parms->index), parms->index);
    rec_dbg(lev, "        capab(%d): 0x%08x", sizeof(parms->capab), parms->capab);
    rec_dbg(lev, "        action(%d): 0x%08x(%s)",
        sizeof(parms->action), parms->action, conv_tc_action(parms->action, 1));
    rec_dbg(lev, "        refcnt(%d): 0x%08x", sizeof(parms->refcnt), parms->refcnt);
    rec_dbg(lev, "        bindcnt(%d): 0x%08x", sizeof(parms->bindcnt), parms->bindcnt);
    rec_dbg(lev, "        update_flags(%d): 0x%08x(%s)",
        sizeof(parms->update_flags), parms->update_flags, flags_list);
}

#ifdef HAVE_LINUX_TC_ACT_TC_CSUM_H
/*
 * convert TCA_CSUM_UPDATE_FLAG_* flags for parse
 */
void conv_tca_csum_update_flags(int flags, char *flags_list, int len, unsigned char debug)
{
    if(!flags) {
        strncpy(flags_list, debug ? "NONE" : "none", len);
        return;
    }
#define _TCA_CSUM_UPDATE_FLAGS(s1, s2) \
    if((flags & TCA_CSUM_UPDATE_FLAG_##s1) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~TCA_CSUM_UPDATE_FLAG_##s1) ? \
            strncat(flags_list, #s2 ",", len - strlen(flags_list) - 1) : \
            strncat(flags_list, #s2, len - strlen(flags_list) - 1);
    _TCA_CSUM_UPDATE_FLAGS(IPV4HDR, ipv4hdr);
    _TCA_CSUM_UPDATE_FLAGS(ICMP, icmp);
    _TCA_CSUM_UPDATE_FLAGS(IGMP, igmp);
    _TCA_CSUM_UPDATE_FLAGS(TCP, tcp);
    _TCA_CSUM_UPDATE_FLAGS(UDP, udp);
    _TCA_CSUM_UPDATE_FLAGS(UDPLITE, udplite);
#undef _TCA_CSUM_UPDATE_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, debug ? "UNKNOWN" : "unknown", len);
}
#endif
#endif
