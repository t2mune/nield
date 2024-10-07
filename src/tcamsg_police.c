/*
 * tcamsg_police.c - traffic control message parser
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
 * parse attribute TCA_POLICE_*
 */
int parse_tca_act_options_police(char *msg, char *mp, struct rtattr *act)
{
    struct rtattr *police[__TCA_POLICE_MAX];

    parse_nested_rtattr(police, TCA_POLICE_MAX, act);

    if(police[TCA_POLICE_TBF]) {
        struct tc_police *tc_police;
        char rate[MAX_STR_SIZE];
        char burst[MAX_STR_SIZE];
        char peakrate[MAX_STR_SIZE];
        char mtu[MAX_STR_SIZE];
        double rate_latency = 0;
        double peakrate_latency = 0;
        char latency[MAX_STR_SIZE];

        if(RTA_PAYLOAD(police[TCA_POLICE_TBF]) < sizeof(*tc_police)) {
            rec_log("error: %s: payload too short", __func__);
            return(1);
        }
        tc_police = (struct tc_police *)RTA_DATA(police[TCA_POLICE_TBF]);
    
        mp = add_log(msg, mp, "index=%d ", tc_police->index);
    
        get_us2tick();
        conv_unit_rate(rate, sizeof(rate), tc_police->rate.rate);
        conv_unit_size(burst, sizeof(burst),
            get_burst_size(tc_police->rate.rate, tc_police->burst));
        rate_latency = get_latency(tc_police->rate.rate,
            tc_police->burst, tc_police->limit);
    
        mp = add_log(msg, mp, "rate=%s burst=%s ", rate, burst);
    
        if(tc_police->peakrate.rate) {
            conv_unit_rate(peakrate, sizeof(peakrate), tc_police->peakrate.rate);
            conv_unit_size(mtu, sizeof(mtu),
                get_burst_size(tc_police->peakrate.rate, tc_police->mtu));
            peakrate_latency =
                get_latency(tc_police->peakrate.rate,
                    tc_police->mtu, tc_police->limit);

            mp = add_log(msg, mp, "peakrate=%s minburst=%s ", peakrate, mtu);
        }
    
        if(rate_latency < peakrate_latency)
            conv_unit_usec(latency, sizeof(latency), peakrate_latency);
        else
            conv_unit_usec(latency, sizeof(latency), rate_latency);
    
        mp = add_log(msg, mp, "latency=%s exceed=%s ",
            latency, conv_tc_police_action(tc_police->action, 0));
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * debug attribute TCA_POLICE_*
 */
void debug_tca_act_options_police(int lev, struct rtattr *act, const char *name)
{
    struct rtattr *police[__TCA_POLICE_MAX];

    if(name)
        rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(act->rta_len));

    parse_nested_rtattr(police, TCA_POLICE_MAX, act);

    if(police[TCA_POLICE_TBF])
        debug_tca_police_tbf(lev+1, police[TCA_POLICE_TBF],
            "TCA_POLICE_TBF");

    if(police[TCA_POLICE_RATE])
        debug_rta_ignore(lev+1, police[TCA_POLICE_RATE],
            "TCA_POLICE_RATE");

    if(police[TCA_POLICE_PEAKRATE])
        debug_rta_ignore(lev+1, police[TCA_POLICE_PEAKRATE],
            "TCA_POLICE_PEAKRATE");

    if(police[TCA_POLICE_AVRATE])
        debug_rta_u32(lev+1, police[TCA_POLICE_AVRATE],
            "TCA_POLICE_AVRATE", NULL);

    if(police[TCA_POLICE_RESULT])
        debug_rta_u32(lev+1, police[TCA_POLICE_RESULT],
            "TCA_POLICE_RESULT", conv_tc_police_action);
}

/*
 * debug attribute TCA_POLICE_TBF
 */
void debug_tca_police_tbf(int lev, struct rtattr *police, const char *name)
{
    struct tc_police *tc_police;
    struct tc_ratespec *rate;
    struct tc_ratespec *peak;

    if(debug_rta_len_chk(lev, police, name, sizeof(*tc_police)))
        return;

    tc_police = (struct tc_police *)RTA_DATA(police);
    rate = &(tc_police->rate);
    peak = &(tc_police->peakrate);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(police->rta_len));
    rec_dbg(lev, "    [ tc_police(%d) ]", sizeof(*tc_police));
    rec_dbg(lev, "        index(%d): %u", sizeof(tc_police->index), tc_police->index);
    rec_dbg(lev, "        action(%d): %d(%s)",
        sizeof(tc_police->action), tc_police->action,
        conv_tc_police_action(tc_police->action, 1));
    rec_dbg(lev, "        limit(%d): %u", sizeof(tc_police->limit), tc_police->limit);
    rec_dbg(lev, "        burst(%d): %u", sizeof(tc_police->burst), tc_police->burst);
    rec_dbg(lev, "        mtu(%d): %u", sizeof(tc_police->mtu), tc_police->mtu);

    debug_tc_ratespec(lev+2, rate, "rate");
    debug_tc_ratespec(lev+2, peak, "peakrate");

    rec_dbg(lev, "        refcnt(%d): %d", sizeof(tc_police->refcnt), tc_police->refcnt);
    rec_dbg(lev, "        bindcnt(%d): %d", sizeof(tc_police->bindcnt), tc_police->bindcnt);
    rec_dbg(lev, "        capab(%d): %u", sizeof(tc_police->capab), tc_police->capab);
}

/*
 * convert TC_POLICE_* action from number to string
 */
const char *conv_tc_police_action(unsigned action, unsigned char debug)
{
#define _TC_POLICE_ACTION(s1, s2) \
    if(action == TC_POLICE_##s1) \
        return(debug ? #s1 : #s2);
    _TC_POLICE_ACTION(UNSPEC, continue);
    _TC_POLICE_ACTION(OK, ok);
    _TC_POLICE_ACTION(RECLASSIFY, reclassify);
    _TC_POLICE_ACTION(SHOT, drop);
    _TC_POLICE_ACTION(PIPE, pipe);
#undef _TC_POLICE_ACTION
    return(debug ? "UNKNOWN" : "unknown");
}
