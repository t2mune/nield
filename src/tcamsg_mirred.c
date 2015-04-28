/*
 * tcamsg_mirred.c - traffic control message parser
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

/*
 * parse mirred options(TCA_ACT_MIRRED: 8)
 */
int parse_tca_act_options_mirred(char *msg, char *mp, struct rtattr *act)
{
    struct rtattr *mirred[__TCA_MIRRED_MAX];

    parse_nested_rtattr(mirred, TCA_MIRRED_MAX, act);

    if(mirred[TCA_MIRRED_PARMS]) {
        struct tc_mirred *parms;
        char ifname[IFNAMSIZ] = "";

        if(RTA_PAYLOAD(mirred[TCA_MIRRED_PARMS]) < sizeof(*parms)) {
            rec_log("error: %s: payload too short", __func__);
            return(1);
        }
        parms = (struct tc_mirred *)RTA_DATA(mirred[TCA_MIRRED_PARMS]);
        if_indextoname_from_lists(parms->ifindex, ifname);
    
        mp = add_log(msg, mp, "index=%d %s to=%s next=%s ",
            parms->index, conv_tca_mirred_action(parms->eaction, 0),
            ifname, conv_tc_action(parms->action, 0));
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * debug mirred options(TCA_ACT_MIRRED: 8)
 */
void debug_tca_act_options_mirred(int lev, struct rtattr *act)
{
    struct rtattr *mirred[__TCA_MIRRED_MAX];

    parse_nested_rtattr(mirred, TCA_MIRRED_MAX, act);

    if(mirred[TCA_MIRRED_TM])
        debug_tca_mirred_tm(lev+1, mirred[TCA_MIRRED_TM],
            "TCA_MIRRED_TM");

    if(mirred[TCA_MIRRED_PARMS])
        debug_tca_mirred_parms(lev+1, mirred[TCA_MIRRED_PARMS],
            "TCA_MIRRED_PARMS");
}

/*
 * debug attribute TCA_MIRRED_TM
 */
void debug_tca_mirred_tm(int lev, struct rtattr *mirred, const char *name)
{
    struct tcf_t *tm;

    if(debug_rta_len_chk(lev, mirred, name, sizeof(*tm)))
        return;

    tm = (struct tcf_t *)RTA_DATA(mirred);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(mirred->rta_len));
    debug_tcf_t(lev+1, tm);
}

/*
 * debug attribute TCA_MIRRED_PARMS
 */
void debug_tca_mirred_parms(int lev, struct rtattr *mirred, const char *name)
{
    struct tc_mirred *parms;
    char ifname[IFNAMSIZ] = "";

    if(debug_rta_len_chk(lev, mirred, name, sizeof(*parms)))
        return;

    parms = (struct tc_mirred *)RTA_DATA(mirred);
    if_indextoname_from_lists(parms->ifindex, ifname);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(mirred->rta_len));
    rec_dbg(lev, "    [ tc_mirred(%d) ]", sizeof(*parms));
    rec_dbg(lev, "        index(%d): %u", sizeof(parms->index), parms->index);
    rec_dbg(lev, "        capab(%d): %u", sizeof(parms->capab), parms->capab);
    rec_dbg(lev, "        action(%d): %d(%s)",
        sizeof(parms->action), parms->action, conv_tc_action(parms->action, 1));
    rec_dbg(lev, "        refcnt(%d): %d", sizeof(parms->refcnt), parms->refcnt);
    rec_dbg(lev, "        bindcnt(%d): %d", sizeof(parms->bindcnt), parms->bindcnt);
    rec_dbg(lev, "        eaction(%d): %d(%s)",
        sizeof(parms->eaction), parms->eaction,
        conv_tca_mirred_action(parms->eaction, 1));
    rec_dbg(lev, "        ifindex(%d): %u(%s)", sizeof(parms->ifindex), parms->ifindex, ifname);
}

/*
 * convert TCA_EGRESS/INGRESS_REDIR/MIRROR from number to string
 */
const char *conv_tca_mirred_action(int action, unsigned char debug)
{
#define _TCA_MIRRED_ACTION(s1, s2) \
    if(action == TCA_##s1) \
        return(debug ? #s1 : #s2);
    _TCA_MIRRED_ACTION(EGRESS_REDIR, mode=redirect direction=egress);
    _TCA_MIRRED_ACTION(EGRESS_MIRROR, mode=mirror direction=egress);
    _TCA_MIRRED_ACTION(INGRESS_REDIR, mode=redirect direction=ingress);
    _TCA_MIRRED_ACTION(INGRESS_MIRROR, mode=mirror direction=ingress);
#undef _TCA_MIRRED_ACTION
    return(debug ? "UNKNOWN" : "mode=unknown direction=unknown");
}
