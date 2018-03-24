/*
 * tcmsg_qdisc_qfq.c - traffic control qdisc message parser
 * Copyright (C) 2018 Tetsumune KISO <t2mune@gmail.com>
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

#if HAVE_DECL_TCA_QFQ_UNSPEC
/*
 * parse qfq options
 */
int parse_tca_options_qfq(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *qfq[__TCA_QFQ_MAX];

    parse_nested_rtattr(qfq, TCA_QFQ_MAX, tca);

    if(qfq[TCA_QFQ_WEIGHT]) {
        if(RTA_PAYLOAD(qfq[TCA_QFQ_WEIGHT]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_QFQ_WEIGHT: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "weight=%u ",
            *(unsigned *)RTA_DATA(qfq[TCA_QFQ_WEIGHT]));
    }

    if(qfq[TCA_QFQ_LMAX]) {
        if(RTA_PAYLOAD(qfq[TCA_QFQ_MAX]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_QFQ_WEIGHT: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "maxpkt=%u(byte) ",
            *(unsigned *)RTA_DATA(qfq[TCA_QFQ_LMAX]));
    }

    return(0);
}

/*
 * debug qfq options
 */
void debug_tca_options_qfq(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *qfq[__TCA_QFQ_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(qfq, TCA_QFQ_MAX, tca);

    if(qfq[TCA_QFQ_WEIGHT])
        debug_rta_u32(lev+1, qfq[TCA_QFQ_WEIGHT],
            "TCA_QFQ_WEIGHT", NULL);

    if(qfq[TCA_QFQ_LMAX])
        debug_rta_u32(lev+1, qfq[TCA_QFQ_LMAX],
            "TCA_QFQ_LMAX", NULL);
}

/*
 * debug tc_qfq_xstats
 */
void debug_tc_qfq_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_qfq_stats *stats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*stats)))
        return;

    stats = (struct tc_qfq_stats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_qfq_stats(%d) ]", sizeof(*stats));
    rec_dbg(lev, "        weight(%d): %u", sizeof(stats->weight), stats->weight);
    rec_dbg(lev, "        lmax(%d): %u", sizeof(stats->lmax), stats->lmax);
}
#endif
