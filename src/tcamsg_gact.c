/*
 * tcamsg_gact.c - traffic control message parser
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
 * parse gact options(TCA_ACT_GACT: 5)
 */
int parse_tca_act_options_gact(char *msg, char *mp, struct rtattr *act)
{
    struct rtattr *gact[__TCA_GACT_MAX];

    parse_nested_rtattr(gact, TCA_GACT_MAX, act);

    if(gact[TCA_GACT_PARMS]) {
        struct tc_gact *parms;

        if(RTA_PAYLOAD(gact[TCA_GACT_PARMS]) < sizeof(*parms)) {
            rec_log("error: %s: TCA_GACT_PARMS: payload too short", __func__);
            return(1);
        }
        parms = (struct tc_gact *)RTA_DATA(gact[TCA_GACT_PARMS]);

        mp = add_log(msg, mp, "index=%d kind=%s ",
            parms->index, conv_tc_action(parms->action, 0));
    }

    if(gact[TCA_GACT_PROB]) {
        struct tc_gact_p *prob;

        if(RTA_PAYLOAD(gact[TCA_GACT_PROB]) < sizeof(*prob)) {
            rec_log("error: %s: TCA_GACT_PROB: payload too short", __func__);
            return(1);
        }
        prob = (struct tc_gact_p *)RTA_DATA(gact);

        mp = add_log(msg, mp, "random(type/value/action)=%s/%d/%s ",
            conv_pgact(prob->ptype, 0), prob->pval,
            conv_tc_action(prob->paction, 0));
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * debug gact options(TCA_ACT_GACT: 5)
 */
void debug_tca_act_options_gact(int lev, struct rtattr *act)
{
    struct rtattr *gact[__TCA_GACT_MAX];

    parse_nested_rtattr(gact, TCA_GACT_MAX, act);

    if(gact[TCA_GACT_TM])
        debug_tca_gact_tm(lev+1, gact[TCA_GACT_TM],
            "TCA_GACT_TM");

    if(gact[TCA_GACT_PARMS])
        debug_tca_gact_parms(lev+1, gact[TCA_GACT_PARMS],
            "TCA_GACT_PARMS");

    if(gact[TCA_GACT_PROB])
        debug_tca_gact_prob(lev+1, gact[TCA_GACT_PROB],
            "TCA_GACT_PROB");
}

/*
 * debug attribute TCA_GACT_TM
 */
void debug_tca_gact_tm(int lev, struct rtattr *gact, const char *name)
{
    struct tcf_t *tm;

    if(debug_rta_len_chk(lev, gact, name, sizeof(*tm)))
        return;

    tm = (struct tcf_t *)RTA_DATA(gact);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(gact->rta_len));
    debug_tcf_t(lev+1, tm);
}

/*
 * debug attribute TCA_GACT_PARMS
 */
void debug_tca_gact_parms(int lev, struct rtattr *gact, const char *name)
{
    struct tc_gact *parms;

    if(debug_rta_len_chk(lev, gact, name, sizeof(*parms)))
        return;

    parms = (struct tc_gact *)RTA_DATA(gact);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(gact->rta_len));
    rec_dbg(lev, "    [ tc_gact(%d) ]", sizeof(*parms));
    rec_dbg(lev, "        index(%d): %u", sizeof(parms->index), parms->index);
    rec_dbg(lev, "        capab(%d): %u", sizeof(parms->capab), parms->capab);
    rec_dbg(lev, "        action(%d): %d(%s)",
        sizeof(parms->action), parms->action, conv_tc_action(parms->action, 1));
    rec_dbg(lev, "        refcnt(%d): %d", sizeof(parms->refcnt), parms->refcnt);
    rec_dbg(lev, "        bindcnt(%d): %d", sizeof(parms->bindcnt), parms->bindcnt);
}

/*
 * debug attribute TCA_GACT_PROB
 */
void debug_tca_gact_prob(int lev, struct rtattr *gact, const char *name)
{
    struct tc_gact_p *prob;

    if(debug_rta_len_chk(lev, gact, name, sizeof(*prob)))
        return;

    prob = (struct tc_gact_p *)RTA_DATA(gact);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(gact->rta_len));
    rec_dbg(lev, "    [ tc_gact_p(%d) ]", sizeof(*prob));
    rec_dbg(lev, "        ptype(%d): %d(%s)",
        sizeof(prob->ptype), prob->ptype, conv_pgact(prob->ptype, 1));
    rec_dbg(lev, "        pval(%d): %d", sizeof(prob->pval), prob->pval);
    rec_dbg(lev, "        paction(%d): %d(%s)",
        sizeof(prob->paction), prob->paction, conv_tc_action(prob->paction, 0));
}

/*
 * convert PGACT_* from number to string
 */
const char *conv_pgact(int pgact, unsigned char debug)
{
#define _PGACT(s1, s2) \
    if(pgact == PGACT_##s1) \
        return(debug ? #s1 : #s2);
    _PGACT(NONE, none);
    _PGACT(NETRAND, netrand);
    _PGACT(DETERM, determ);
#undef _PGACT
    return(debug ? "UNKNOWN" : "unknown");
}
