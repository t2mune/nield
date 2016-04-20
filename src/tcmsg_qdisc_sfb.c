/*
 * tcmsg_qdisc_sfb.c - traffic control qdisc message parser
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

#if HAVE_DECL_TCA_SFB_UNSPEC
/*
 * parse sfb options
 */
int parse_tca_options_sfb(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *sfb[__TCA_NETEM_MAX];

    parse_nested_rtattr(sfb, TCA_SFB_MAX, tca);

    if(sfb[TCA_SFB_PARMS]) {
        struct tc_sfb_qopt *qopt;
        char rehash[MAX_STR_SIZE];
        char warmup[MAX_STR_SIZE];

        if(RTA_PAYLOAD(sfb[TCA_SFB_PARMS]) < sizeof(*qopt)) {
            rec_log("error: %s: TCA_SFB_PARMS: payload too short", __func__);
            return(1);
        }
        qopt = (struct tc_sfb_qopt *)RTA_DATA(sfb[TCA_SFB_PARMS]);

        conv_unit_usec(rehash, sizeof(rehash), qopt->rehash_interval * 1000);
        conv_unit_usec(warmup, sizeof(warmup), qopt->warmup_time * 1000);

        *mp = add_log(msg, *mp, "limit=%u(packet) max=%u(packet) "
            "target=%u(packet) increment=%.5f decrement=%.5f "
            "penalty-rate=%u(packet/s) penalty-burst=%u(packet) "
            "rehash=%s warmup=%s ",
            qopt->limit, qopt->max, qopt->bin_size,
            (double)qopt->increment / SFB_MAX_PROB,
            (double)qopt->decrement / SFB_MAX_PROB,
            qopt->penalty_rate, qopt->penalty_burst,
            rehash, warmup);
    }

    return(0);
}

/*
 * debug sfb options
 */
void debug_tca_options_sfb(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *sfb[__TCA_SFB_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(sfb, TCA_SFB_MAX, tca);

    if(sfb[TCA_SFB_PARMS])
        debug_tca_sfb_parms(lev+1, sfb[TCA_SFB_PARMS],
            "TCA_SFB_PARMS");
}

/*
 * debug attribute TCA_SFB_PARMS
 */
void debug_tca_sfb_parms(int lev, struct rtattr *sfb, const char *name)
{
    struct tc_sfb_qopt *qopt;

    if(debug_rta_len_chk(lev, sfb, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_sfb_qopt *)RTA_DATA(sfb);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(sfb->rta_len));
    rec_dbg(lev, "    [ tc_stats(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        rehash_interval(%d): %u",
        sizeof(qopt->rehash_interval), qopt->rehash_interval);
    rec_dbg(lev, "        warmup_time(%d): %u",
        sizeof(qopt->warmup_time), qopt->warmup_time);
    rec_dbg(lev, "        max(%d): %u", sizeof(qopt->max), qopt->max);
    rec_dbg(lev, "        bin_size(%d): %u", sizeof(qopt->bin_size), qopt->bin_size);
    rec_dbg(lev, "        increment(%d): %u", sizeof(qopt->increment), qopt->increment);
    rec_dbg(lev, "        decrement(%d): %u", sizeof(qopt->decrement), qopt->decrement);
    rec_dbg(lev, "        limit(%d): %u", sizeof(qopt->limit), qopt->limit);
    rec_dbg(lev, "        penalty_rate(%d): %u",
        sizeof(qopt->penalty_rate), qopt->penalty_rate);
    rec_dbg(lev, "        penalty_burst(%d): %u",
        sizeof(qopt->penalty_burst), qopt->penalty_burst);
}

/*
 * debug tc_sfb_xstats
 */
void debug_tc_sfb_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_sfb_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_sfb_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_sfb_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        earlydrop(%d): %u", sizeof(xstats->earlydrop), xstats->earlydrop);
    rec_dbg(lev, "        penaltydrop(%d): %u", sizeof(xstats->penaltydrop), xstats->penaltydrop);
    rec_dbg(lev, "        bucketdrop(%d): %u", sizeof(xstats->bucketdrop), xstats->bucketdrop);
    rec_dbg(lev, "        queuedrop(%d): %u", sizeof(xstats->queuedrop), xstats->queuedrop);
    rec_dbg(lev, "        childdrop(%d): %u", sizeof(xstats->childdrop), xstats->childdrop);
    rec_dbg(lev, "        marked(%d): %u", sizeof(xstats->marked), xstats->marked);
    rec_dbg(lev, "        maxqlen(%d): %u", sizeof(xstats->maxqlen), xstats->maxqlen);
    rec_dbg(lev, "        maxprob(%d): %u", sizeof(xstats->maxprob), xstats->maxprob);
    rec_dbg(lev, "        avgprob(%d): %u", sizeof(xstats->avgprob), xstats->avgprob);
}
#endif
