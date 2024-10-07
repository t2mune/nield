/*
 * tcmsg_qdisc_fq_codel.c - traffic control qdisc message parser
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

#if HAVE_DECL_TCA_FQ_CODEL_UNSPEC
/*
 * parse fq_codel options
 */
int parse_tca_options_fq_codel(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *fq_codel[__TCA_FQ_CODEL_MAX];

    parse_nested_rtattr(fq_codel, TCA_FQ_CODEL_MAX, tca);

    if(fq_codel[TCA_FQ_CODEL_LIMIT]) {
        if(RTA_PAYLOAD(fq_codel[TCA_FQ_CODEL_LIMIT]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_FQ_CODEL_LIMIT: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "limit=%u(packet) ",
            *(unsigned *)RTA_DATA(fq_codel[TCA_FQ_CODEL_LIMIT]));
    }

    if(fq_codel[TCA_FQ_CODEL_FLOWS]) {
        if(RTA_PAYLOAD(fq_codel[TCA_FQ_CODEL_FLOWS]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_FQ_CODEL_FLOWS: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "flows=%u ",
            *(unsigned *)RTA_DATA(fq_codel[TCA_FQ_CODEL_FLOWS]));
    }

    if(fq_codel[TCA_FQ_CODEL_QUANTUM]) {
        if(RTA_PAYLOAD(fq_codel[TCA_FQ_CODEL_QUANTUM]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_FQ_CODEL_QUANTUM: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "quantum=%u(byte) ",
            *(unsigned *)RTA_DATA(fq_codel[TCA_FQ_CODEL_QUANTUM]));
    }

    if(fq_codel[TCA_FQ_CODEL_TARGET]) {
        char target[MAX_STR_SIZE];

        if(RTA_PAYLOAD(fq_codel[TCA_FQ_CODEL_TARGET]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_FQ_CODEL_TARGET: payload too short", __func__);
            return(1);
        }
        conv_unit_usec(target, sizeof(target),
            (double)*(unsigned *)RTA_DATA(fq_codel[TCA_FQ_CODEL_TARGET]));
        *mp = add_log(msg, *mp, "target=%s ", target);
    }

    if(fq_codel[TCA_FQ_CODEL_INTERVAL]) {
        char interval[MAX_STR_SIZE];

        if(RTA_PAYLOAD(fq_codel[TCA_FQ_CODEL_INTERVAL]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_FQ_CODEL_INTERVAL: payload too short", __func__);
            return(1);
        }
        conv_unit_usec(interval, sizeof(interval),
            (double)*(unsigned *)RTA_DATA(fq_codel[TCA_FQ_CODEL_INTERVAL]));
        *mp = add_log(msg, *mp, "interval=%s ", interval);
    }

    if(fq_codel[TCA_FQ_CODEL_ECN]) {
        if(RTA_PAYLOAD(fq_codel[TCA_FQ_CODEL_ECN]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_FQ_CODEL_ECN: payload too short", __func__);
            return(1);
        }
        if(*(unsigned *)RTA_DATA(fq_codel[TCA_FQ_CODEL_ECN]))
            *mp = add_log(msg, *mp, "ecn=on ");
    }

    return(0);
}

/*
 * debug fq_codel options
 */
void debug_tca_options_fq_codel(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *fq_codel[__TCA_FQ_CODEL_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(fq_codel, TCA_FQ_CODEL_MAX, tca);

    if(fq_codel[TCA_FQ_CODEL_TARGET])
        debug_rta_u32(lev+1, fq_codel[TCA_FQ_CODEL_TARGET],
            "TCA_FQ_CODEL_TARGET", NULL);

    if(fq_codel[TCA_FQ_CODEL_LIMIT])
        debug_rta_u32(lev+1, fq_codel[TCA_FQ_CODEL_LIMIT],
            "TCA_FQ_CODEL_LIMIT", NULL);

    if(fq_codel[TCA_FQ_CODEL_INTERVAL])
        debug_rta_u32(lev+1, fq_codel[TCA_FQ_CODEL_INTERVAL],
            "TCA_FQ_CODEL_INTERVAL", NULL);

    if(fq_codel[TCA_FQ_CODEL_ECN])
        debug_rta_u32(lev+1, fq_codel[TCA_FQ_CODEL_ECN],
            "TCA_FQ_CODEL_ECN", NULL);

    if(fq_codel[TCA_FQ_CODEL_FLOWS])
        debug_rta_u32(lev+1, fq_codel[TCA_FQ_CODEL_FLOWS],
            "TCA_FQ_CODEL_FLOWS", NULL);

    if(fq_codel[TCA_FQ_CODEL_QUANTUM])
        debug_rta_u32(lev+1, fq_codel[TCA_FQ_CODEL_QUANTUM],
            "TCA_FQ_CODEL_QUANTUM", NULL);
}

/*
 * debug tc_fq_codel_xstats
 */
void debug_tc_fq_codel_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_fq_codel_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_fq_codel_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_fq_codel_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        type(%d): %u", sizeof(xstats->type), xstats->type);

    if(xstats->type == TCA_FQ_CODEL_XSTATS_QDISC) {
        struct tc_fq_codel_qd_stats *qd_stats = &(xstats->qdisc_stats);

        rec_dbg(lev, "        [ tc_fq_codel_qd_stats qdisc_stats(%d) ]",
            sizeof(*qd_stats));
        rec_dbg(lev, "            maxpacket(%d): %u",
            sizeof(qd_stats->maxpacket), qd_stats->maxpacket);
        rec_dbg(lev, "            drop_overlimit(%d): %u",
            sizeof(qd_stats->drop_overlimit), qd_stats->drop_overlimit);
        rec_dbg(lev, "            ecn_mark(%d): %u",
            sizeof(qd_stats->ecn_mark), qd_stats->ecn_mark);
        rec_dbg(lev, "            new_flow_count(%d): %u",
            sizeof(qd_stats->new_flow_count), qd_stats->new_flow_count);
        rec_dbg(lev, "            new_flows_len(%d): %u",
            sizeof(qd_stats->new_flows_len), qd_stats->new_flows_len);
        rec_dbg(lev, "            old_flows_len(%d): %u",
            sizeof(qd_stats->old_flows_len), qd_stats->old_flows_len);
    } else if(xstats->type == TCA_FQ_CODEL_XSTATS_QDISC) {
        struct tc_fq_codel_cl_stats *cl_stats = &(xstats->class_stats);

        rec_dbg(lev, "        [ tc_fq_codel_cl_stats class_stats(%d) ]",
            sizeof(*cl_stats));
        rec_dbg(lev, "            deficit(%d): %d",
            sizeof(cl_stats->deficit), cl_stats->deficit);
        rec_dbg(lev, "            ldelay(%d): %u",
            sizeof(cl_stats->ldelay), cl_stats->ldelay);
        rec_dbg(lev, "            count(%d): %u",
            sizeof(cl_stats->count), cl_stats->count);
        rec_dbg(lev, "            lastcount(%d): %u",
            sizeof(cl_stats->lastcount), cl_stats->lastcount);
        rec_dbg(lev, "            dropping(%d): %u",
            sizeof(cl_stats->dropping), cl_stats->dropping);
        rec_dbg(lev, "            drop_next(%d): %d",
            sizeof(cl_stats->drop_next), cl_stats->drop_next);
    }
}
#endif
