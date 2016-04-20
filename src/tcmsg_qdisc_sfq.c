/*
 * tcmsg_qdisc_sfq.c - traffic control qdisc message parser
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

/*
 * parse sfq options
 */
int parse_tca_options_sfq(char *msg, char **mp, struct rtattr *tca)
{
    struct tc_sfq_qopt *qopt;

    if(RTA_PAYLOAD(tca) < sizeof(*qopt)) {
        rec_log("error: %s: TCA_OPTIONS: payaload too short", __func__);
        return(1);
    }
    qopt = (struct tc_sfq_qopt *)RTA_DATA(tca);

    *mp = add_log(msg, *mp,
        "quantum=%u(byte) perturb=%d(second) limit=%u(packet) divisor=%u flows=%u ",
        qopt->quantum, qopt->perturb_period, qopt->limit, qopt->divisor, qopt->flows);

#ifdef HAVE_STRUCT_TC_SFQ_QOPT_V1_V0
    struct tc_sfq_qopt_v1 *qopt_v1 = NULL;

    if(RTA_PAYLOAD(tca) >= sizeof(*qopt_v1))
        qopt_v1 = (struct tc_sfq_qopt_v1 *)RTA_DATA(tca);

    if(qopt_v1) {
        char list[MAX_STR_SIZE] = "";
        char min[MAX_STR_SIZE] = "";
        char max[MAX_STR_SIZE] = "";

        conv_unit_size(min, sizeof(min), qopt_v1->qth_min);
        conv_unit_size(max, sizeof(max), qopt_v1->qth_max);

        *mp = add_log(msg, *mp, "depth=%u(packet) headdrop=%s min=%s max=%s ",
            qopt_v1->depth, qopt_v1->headdrop ? "on" : "off", min, max);

        if(qopt_v1->flags) {
            conv_tc_red_flags(qopt_v1->flags, list, sizeof(list), 0);
            *mp = add_log(msg, *mp, "flag=%s ", list);
        }
        *mp = add_log(msg, *mp, "probability=%g(%%) ", qopt_v1->max_P / pow(2, 32) * 100);
    }
#endif

    return(0);
}

/*
 * debug sfq options
 */
void debug_tca_options_sfq(int lev, struct rtattr *tca, const char *name)
{
    struct tc_sfq_qopt *qopt;
    struct tc_sfqred_stats *stats = NULL;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_sfq_qopt *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));

#ifdef HAVE_STRUCT_TC_SFQ_QOPT_V1_V0
    struct tc_sfq_qopt_v1 *qopt_v1 = NULL;

    if(RTA_PAYLOAD(tca) >= sizeof(*qopt_v1)) {
        qopt_v1 = (struct tc_sfq_qopt_v1 *)RTA_DATA(tca);
        stats = &(qopt_v1->stats);
    }

    if(qopt_v1) {
        char list[MAX_STR_SIZE] = "";

        conv_tc_red_flags(qopt_v1->flags, list, sizeof(list), 1);

        rec_dbg(lev, "    [ tc_sfq_qopt_v1(%d) ]", sizeof(*qopt_v1));
        rec_dbg(lev, "        [ tc_sfq_qopt v0(%d) ]", sizeof(qopt_v1->v0));
        rec_dbg(lev, "            quantum(%d): %u", sizeof(qopt->quantum), qopt->quantum);
        rec_dbg(lev, "            perturb_period(%d): %d",
            sizeof(qopt->perturb_period), qopt->perturb_period);
        rec_dbg(lev, "            limit(%d): %u", sizeof(qopt->limit), qopt->limit);
        rec_dbg(lev, "            divisor(%d): %u", sizeof(qopt->divisor), qopt->divisor);
        rec_dbg(lev, "            flows(%d): %u", sizeof(qopt->flows), qopt->flows);
        rec_dbg(lev, "        depth(%d): %u", sizeof(qopt_v1->depth), qopt_v1->depth);
        rec_dbg(lev, "        headdrop(%d): %u", sizeof(qopt_v1->headdrop), qopt_v1->headdrop);
        rec_dbg(lev, "        limit(%d): %u", sizeof(qopt_v1->limit), qopt_v1->limit);
        rec_dbg(lev, "        qth_min(%d): %u", sizeof(qopt_v1->qth_min), qopt_v1->qth_min);
        rec_dbg(lev, "        qth_max(%d): %u", sizeof(qopt_v1->qth_max), qopt_v1->qth_max);
        rec_dbg(lev, "        Wlog(%d): %d", sizeof(qopt_v1->Wlog), qopt_v1->Wlog);
        rec_dbg(lev, "        Plog(%d): %d", sizeof(qopt_v1->Plog), qopt_v1->Plog);
        rec_dbg(lev, "        Scell_log(%d): %d",
            sizeof(qopt_v1->Scell_log), qopt_v1->Scell_log);
        rec_dbg(lev, "        flags(%d): %d(%s)",
            sizeof(qopt_v1->flags), qopt_v1->flags, list);
        rec_dbg(lev, "        max_P(%d): %u",
            sizeof(qopt_v1->max_P), qopt_v1->max_P);
        rec_dbg(lev, "        [ tc_sfqred_stats stats(%d) ]", sizeof(qopt_v1->stats));
        rec_dbg(lev, "            prob_drop(%d): %u",
            sizeof(stats->prob_drop), stats->prob_drop);
        rec_dbg(lev, "            forced_drop(%d): %u",
            sizeof(stats->forced_drop), stats->forced_drop);
        rec_dbg(lev, "            prob_mark(%d): %u",
            sizeof(stats->prob_mark), stats->prob_mark);
        rec_dbg(lev, "            forced_mark(%d): %u",
            sizeof(stats->forced_mark), stats->forced_mark);
        rec_dbg(lev, "            prob_mark_head(%d): %u",
            sizeof(stats->prob_mark_head), stats->prob_mark_head);
        rec_dbg(lev, "            forced_mark_head(%d): %u",
            sizeof(stats->forced_mark_head), stats->forced_mark_head);

        return;
    }
#endif

    rec_dbg(lev, "    [ tc_sfq_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        quantum(%d): %u", sizeof(qopt->quantum), qopt->quantum);
    rec_dbg(lev, "        perturb_period(%d): %d",
        sizeof(qopt->perturb_period), qopt->perturb_period);
    rec_dbg(lev, "        limit(%d): %u", sizeof(qopt->limit), qopt->limit);
    rec_dbg(lev, "        divisor(%d): %u", sizeof(qopt->divisor), qopt->divisor);
    rec_dbg(lev, "        flows(%d): %u", sizeof(qopt->flows), qopt->flows);
}

#ifdef HAVE_STRUCT_TC_SFQ_XSTATS_ALLOT
/*
 * debug tc_sfq_xstats
 */
void debug_tc_sfq_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_sfq_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_sfq_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        allot(%d): %d", sizeof(xstats->allot), xstats->allot);
}
#endif
