/*
 * tcamsg_pedit.c - traffic control message parser
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

/*
 * parse pedit options(TCA_ACT_PEDIT: 7)
 */
int parse_tca_act_options_pedit(char *msg, char *mp, struct rtattr *act)
{
    struct rtattr *pedit[__TCA_PEDIT_MAX];
    char *mp_tmp;

    parse_nested_rtattr(pedit, TCA_PEDIT_MAX, act);

    if(pedit[TCA_PEDIT_PARMS]) {
        struct tc_pedit_sel *parms;
        struct tc_pedit_key *keys;
        int len, i;

        if(RTA_PAYLOAD(pedit[TCA_PEDIT_PARMS]) < sizeof(*parms)) {
            rec_log("error: %s: TCA_PEDIT_PARMS: payload too short", __func__);
            return(1);
        }
        parms = (struct tc_pedit_sel *)RTA_DATA(pedit[TCA_PEDIT_PARMS]);

        len = sizeof(*parms) + (sizeof(*keys) * parms->nkeys);
        if(RTA_PAYLOAD(pedit[TCA_PEDIT_PARMS]) < len) {
            rec_log("error: %s: TCA_PEDIT_PARMS: payload too short", __func__);
            return(1);
        }

        mp = add_log(msg, mp, "index=%d ", parms->index);
        mp_tmp = mp;
    
        keys = parms->keys;
        if(!keys) {
            rec_log("error: %s: no key", __func__);
            return(1);
        }
    
        for(i = 0; i < parms->nkeys; i++, keys++, mp = mp_tmp) {
            mp = add_log(msg, mp, "key=%d value=0x%08x/0x%08x offset=%d "
                "at=%d offmask=0x%08x shift=%d next=%s ",
                i+1, ntohl(keys->val), ntohl(keys->mask), keys->off,
                keys->at, ntohl(keys->offmask), keys->shift,
                conv_tc_action(parms->action, 0));
            rec_log("%s", msg);
        }

        return(0);
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * debug pedit options(TCA_ACT_PEDIT: 7)
 */
void debug_tca_act_options_pedit(int lev, struct rtattr *act)
{
    struct rtattr *pedit[__TCA_PEDIT_MAX];

    parse_nested_rtattr(pedit, TCA_PEDIT_MAX, act);

    if(pedit[TCA_PEDIT_TM])
        debug_tca_pedit_tm(lev, pedit[TCA_PEDIT_TM],
            "TCA_PEDIT_TM");

    if(pedit[TCA_PEDIT_PARMS])
        debug_tca_pedit_parms(lev, pedit[TCA_PEDIT_PARMS],
            "TCA_PEDIT_PARMS");
}

/*
 * debug attribute TCA_PEDIT_TM
 */
void debug_tca_pedit_tm(int lev, struct rtattr *pedit, const char *name)
{
    struct tcf_t *tm;

    if(debug_rta_len_chk(lev, pedit, name, sizeof(*tm)))
        return;

    tm = (struct tcf_t *)RTA_DATA(pedit);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(pedit->rta_len));
    debug_tcf_t(lev+1, tm);
}

/*
 * debug attribute TCA_PEDIT_PARMS
 */
void debug_tca_pedit_parms(int lev, struct rtattr *pedit, const char *name)
{
    struct tc_pedit_sel *parms;

    if(debug_rta_len_chk(lev, pedit, name, sizeof(*parms)))
        return;

    parms = (struct tc_pedit_sel *)RTA_DATA(pedit);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(pedit->rta_len));
    rec_dbg(lev, "    [ tc_pedit_sel(%d) ]", sizeof(*parms));
    rec_dbg(lev, "        index(%d): 0x%08x", sizeof(parms->index), parms->index);
    rec_dbg(lev, "        capab(%d): 0x%08x", sizeof(parms->capab), parms->capab);
    rec_dbg(lev, "        action(%d): 0x%08x(%s)",
        sizeof(parms->action), parms->action, conv_tc_action(parms->action, 1));
    rec_dbg(lev, "        refcnt(%d): 0x%08x", sizeof(parms->refcnt), parms->refcnt);
    rec_dbg(lev, "        bindcnt(%d): 0x%08x", sizeof(parms->bindcnt), parms->bindcnt);
    rec_dbg(lev, "        nkeys(%d): 0x%02x", sizeof(parms->nkeys), parms->nkeys);
    rec_dbg(lev, "        flags(%d): 0x%02x", sizeof(parms->flags), parms->flags);

    int i, len;
    struct tc_pedit_key *keys = parms->keys;

    len = sizeof(*parms) + (sizeof(*keys) * parms->nkeys);
    if(RTA_PAYLOAD(pedit) < len) {
        rec_dbg(lev, "        nkeys[0](%d): -- payload too short --",
            RTA_PAYLOAD(pedit) - sizeof(*parms));
        return;
    }

    for(i = 0; i < parms->nkeys; i++, keys++) {
        rec_dbg(lev+2, "[ tc_pedit_key keys[%d](%d) ]", i, sizeof(*keys));
        rec_dbg(lev+3, "    mask(%d): 0x%08x(0x%08x)",
            sizeof(keys->mask), keys->mask, ntohl(keys->mask)); /* AND */
        rec_dbg(lev+3, "    val(%d): 0x%08x(0x%08x)",
            sizeof(keys->val), keys->val, ntohl(keys->val)); /* XOR */
        rec_dbg(lev+3, "    off(%d): %d", sizeof(keys->off), keys->off); /* Offset */
        rec_dbg(lev+3, "    at(%d): %d", sizeof(keys->at), keys->at);
        rec_dbg(lev+3, "    offmask(%d): 0x%08x(0x%08x)",
            sizeof(keys->offmask), keys->offmask, ntohl(keys->offmask));
        rec_dbg(lev+3, "    shift(%d): %d", sizeof(keys->shift), keys->shift);
    }
}
