/*
 * tcamsg_nat.c - traffic control message parser
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

#ifdef HAVE_LINUX_TC_ACT_TC_NAT_H
/*
 * parse nat options(TCA_ACT_NAT: 9)
 */
int parse_tca_act_options_nat(char *msg, char *mp, struct rtattr *act)
{
    struct rtattr *nat[__TCA_NAT_MAX];

    parse_nested_rtattr(nat, TCA_NAT_MAX, act);

    if(nat[TCA_NAT_PARMS]) {
        struct tc_nat *parms;
        char old[INET_ADDRSTRLEN+1] = "";
        char new[INET_ADDRSTRLEN+1] = "";
        int i, mask;

        if(RTA_PAYLOAD(nat[TCA_NAT_PARMS]) < sizeof(*parms)) {
            rec_log("error: %s: payload too short", __func__);
            return(1);
        }
        parms = (struct tc_nat *)RTA_DATA(nat[TCA_NAT_PARMS]);
    
        inet_ntop(AF_INET, &(parms->old_addr), old, sizeof(old));
        inet_ntop(AF_INET, &(parms->new_addr), new, sizeof(new));
    
        for(i = 0, mask = 0; i < 32; i++)
            if(parms->mask & (1 << i))
                ++mask;
    
        mp = add_log(msg, mp, "index=%d from=%s/%d to=%s direction=%s ",
            parms->index, old, mask, new,
            (parms->flags & TCA_NAT_FLAG_EGRESS) ? "egress" : "ingress");
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * debug nat options(TCA_ACT_NAT: 9)
 */
void debug_tca_act_options_nat(int lev, struct rtattr *act)
{
    struct rtattr *nat[__TCA_NAT_MAX];

    parse_nested_rtattr(nat, TCA_NAT_MAX, act);

    if(nat[TCA_NAT_PARMS])
        debug_tca_nat_parms(lev+1, nat[TCA_NAT_PARMS],
            "TCA_NAT_PARMS");

    if(nat[TCA_NAT_TM])
        debug_tca_nat_tm(lev+1, nat[TCA_NAT_TM],
            "TCA_NAT_TM");
}

/*
 * debug attribute TCA_NAT_PARMS
 */
void debug_tca_nat_parms(int lev, struct rtattr *nat, const char *name)
{
    struct tc_nat *parms;
    char old[INET_ADDRSTRLEN+1] = "";
    char new[INET_ADDRSTRLEN+1] = "";
    char mask[INET_ADDRSTRLEN+1] = "";

    if(debug_rta_len_chk(lev, nat, name, sizeof(*parms)))
        return;

    parms = (struct tc_nat *)RTA_DATA(nat);
    inet_ntop(AF_INET, &(parms->old_addr), old, sizeof(old));
    inet_ntop(AF_INET, &(parms->new_addr), new, sizeof(new));
    inet_ntop(AF_INET, &(parms->mask), mask, sizeof(mask));

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(nat->rta_len));
    rec_dbg(lev, "    [ tc_nat(%d) ]", sizeof(*parms));
    rec_dbg(lev, "        index(%d): %u", sizeof(parms->index), parms->index);
    rec_dbg(lev, "        capab(%d): %u", sizeof(parms->capab), parms->capab);
    rec_dbg(lev, "        action(%d): %d(%s)",
        sizeof(parms->action), parms->action, conv_tc_action(parms->action, 1));
    rec_dbg(lev, "        refcnt(%d): %d", sizeof(parms->refcnt), parms->refcnt);
    rec_dbg(lev, "        bindcnt(%d): %d", sizeof(parms->bindcnt), parms->bindcnt);
    rec_dbg(lev, "        old_addr(%d): 0x%08x(%s)",
        sizeof(parms->old_addr), parms->old_addr, old);
    rec_dbg(lev, "        new_addr(%d): 0x%08x(%s)",
        sizeof(parms->new_addr), parms->new_addr, new);
    rec_dbg(lev, "        mask(%d): 0x%08x(%s)",
        sizeof(parms->mask), parms->mask, mask);
    rec_dbg(lev, "        flags(%d): 0x%08x(%s)",
        sizeof(parms->flags), parms->flags,
        (parms->flags & TCA_NAT_FLAG_EGRESS) ? "EGRESS" : "INGRESS");
}

/*
 * debug attribute TCA_NAT_TM
 */
void debug_tca_nat_tm(int lev, struct rtattr *nat, const char *name)
{
    struct tcf_t *tm;

    if(debug_rta_len_chk(lev, nat, name, sizeof(*tm)))
        return;

    tm = (struct tcf_t *)RTA_DATA(nat);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(nat->rta_len));
    debug_tcf_t(lev+1, tm);
}
#endif
