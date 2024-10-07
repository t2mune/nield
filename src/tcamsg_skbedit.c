/*
 * tcamsg_skbedit.c - traffic control message parser
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

#ifdef HAVE_LINUX_TC_ACT_TC_SKBEDIT_H
/*
 * parse skbedit options(TCA_ACT_SKBEDIT: 11)
 */
int parse_tca_act_options_skbedit(char *msg, char *mp, struct rtattr *act)
{
    struct rtattr *skb[__TCA_SKBEDIT_MAX];
    struct tc_skbedit *parms = NULL;

    parse_nested_rtattr(skb, TCA_SKBEDIT_MAX, act);

    if(skb[TCA_SKBEDIT_PARMS]) {
        if(RTA_PAYLOAD(skb[TCA_SKBEDIT_PARMS]) < sizeof(*parms)) {
            rec_log("error: %s: TCA_SKBEDIT_PARMS: payload too short", __func__);
            return(1);
        }
        parms = (struct tc_skbedit *)RTA_DATA(skb[TCA_SKBEDIT_PARMS]);
        mp = add_log(msg, mp, "index=%d ", parms->index);
    }

    if(skb[TCA_SKBEDIT_PRIORITY]) {
        if(RTA_PAYLOAD(skb[TCA_SKBEDIT_PRIORITY]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_SKBEDIT_PRIORITY: payload too short", __func__);
            return(1);
        }
        mp = add_log(msg, mp, "priority=0x%x ",
            *(unsigned *)RTA_DATA(skb[TCA_SKBEDIT_PRIORITY]));
    }

    if(skb[TCA_SKBEDIT_QUEUE_MAPPING]) {
        if(RTA_PAYLOAD(skb[TCA_SKBEDIT_QUEUE_MAPPING]) < sizeof(unsigned short)) {
            rec_log("error: %s: TCA_SKBEDIT_QUEUE_MAPPING: payload too short", __func__);
            return(1);
        }
        mp = add_log(msg, mp, "queue-mapping=%u ",
            *(unsigned *)RTA_DATA(skb[TCA_SKBEDIT_QUEUE_MAPPING]));
    }

#if HAVE_DECL_TCA_SKBEDIT_MARK
    if(skb[TCA_SKBEDIT_MARK]) {
        if(RTA_PAYLOAD(skb[TCA_SKBEDIT_MARK]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_SKBEDIT_MARK: payload too short", __func__);
            return(1);
        }
        mp = add_log(msg, mp, "mark=%u ",
            *(unsigned *)RTA_DATA(skb[TCA_SKBEDIT_MARK]));
    }
#endif

    if(parms)
        mp = add_log(msg, mp, "next=%s ", conv_tc_action(parms->action, 0));

    rec_log("%s", msg);

    return(0);
}

/*
 * debug skbedit options(TCA_ACT_SKBEDIT: 11)
 */
void debug_tca_act_options_skbedit(int lev, struct rtattr *act)
{
    struct rtattr *skb[__TCA_SKBEDIT_MAX];

    parse_nested_rtattr(skb, TCA_SKBEDIT_MAX, act);

    if(skb[TCA_SKBEDIT_TM])
        debug_tca_skbedit_tm(lev+1, skb[TCA_SKBEDIT_TM],
            "TCA_SKBEDIT_TM");

    if(skb[TCA_SKBEDIT_PARMS])
        debug_tca_skbedit_parms(lev+1, skb[TCA_SKBEDIT_PARMS],
            "TCA_SKBEDIT_PARMS");

    if(skb[TCA_SKBEDIT_PRIORITY])
        debug_rta_u32x(lev+1, skb[TCA_SKBEDIT_PRIORITY],
            "TCA_SKBEDIT_PRIORITY", NULL);

    if(skb[TCA_SKBEDIT_QUEUE_MAPPING])
        debug_rta_u16(lev+1, skb[TCA_SKBEDIT_QUEUE_MAPPING],
            "TCA_SKBEDIT_QUEUE_MAPPING", NULL);

#if HAVE_DECL_TCA_SKBEDIT_MARK
    if(skb[TCA_SKBEDIT_MARK])
        debug_rta_u32(lev+1, skb[TCA_SKBEDIT_MARK],
            "TCA_SKBEDIT_MARK", NULL);
#endif
}

/*
 * debug attribute TCA_SKBEDIT_TM
 */
void debug_tca_skbedit_tm(int lev, struct rtattr *skb, const char *name)
{
    struct tcf_t *tm;

    if(debug_rta_len_chk(lev, skb, name, sizeof(*tm)))
        return;

    tm = (struct tcf_t *)RTA_DATA(skb);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(skb->rta_len));
    debug_tcf_t(lev+1, tm);
}

/*
 * debug attribute TCA_SKBEDIT_PARMS
 */
void debug_tca_skbedit_parms(int lev, struct rtattr *skb, const char *name)
{
    struct tc_skbedit *parms;

    if(debug_rta_len_chk(lev, skb, name, sizeof(*parms)))
        return;

    parms = (struct tc_skbedit *)RTA_DATA(skb);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(skb->rta_len));
    rec_dbg(lev, "    [ tc_skbedit(%d) ]", sizeof(*parms));
    rec_dbg(lev, "        index(%d): %u", sizeof(parms->index), parms->index);
    rec_dbg(lev, "        capab(%d): %u", sizeof(parms->capab), parms->capab);
    rec_dbg(lev, "        action(%d): %d(%s)",
        sizeof(parms->action), parms->action, conv_tc_action(parms->action, 0));
    rec_dbg(lev, "        refcnt(%d): %d", sizeof(parms->refcnt), parms->refcnt);
    rec_dbg(lev, "        bindcnt(%d): %d", sizeof(parms->bindcnt), parms->bindcnt);
}
#endif
