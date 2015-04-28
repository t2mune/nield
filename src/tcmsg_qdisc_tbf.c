/*
 * tcmsg_qdisc_tbf.c - traffic control qdisc message parser
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
 * parse tbf options
 */
int parse_tca_options_tbf(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *tbf[__TCA_TBF_MAX];

    parse_nested_rtattr(tbf, TCA_TBF_MAX, tca);

    if(tbf[TCA_TBF_PARMS]) {
        struct tc_tbf_qopt *qopt;
        char rate[MAX_STR_SIZE];
        char burst[MAX_STR_SIZE];
        char peakrate[MAX_STR_SIZE];
        char mtu[MAX_STR_SIZE];
        double rate_latency = 0;
        double peakrate_latency = 0;
        char latency[MAX_STR_SIZE];

        if(RTA_PAYLOAD(tbf[TCA_TBF_PARMS]) < sizeof(*qopt)) {
            rec_log("error: %s: TCA_TBF_PARMS: payload too short", __func__);
            return(1);
        }
        qopt = (struct tc_tbf_qopt *)RTA_DATA(tbf[TCA_TBF_PARMS]);

        get_us2tick();
        conv_unit_rate(rate, sizeof(rate), qopt->rate.rate);
        conv_unit_size(burst, sizeof(burst),
            get_burst_size(qopt->rate.rate, qopt->buffer));
        rate_latency = get_latency(qopt->rate.rate, qopt->buffer, qopt->limit);

        *mp = add_log(msg, *mp, "rate=%s burst=%s ", rate, burst);

        if(qopt->peakrate.rate) {
            conv_unit_rate(peakrate, sizeof(peakrate), qopt->peakrate.rate);
            conv_unit_size(mtu, sizeof(mtu),
                get_burst_size(qopt->peakrate.rate, qopt->mtu));
            peakrate_latency = get_latency(qopt->peakrate.rate, qopt->mtu, qopt->limit);

            *mp = add_log(msg, *mp, "peakrate=%s minburst=%s ", peakrate, mtu);
        }

        if(rate_latency < peakrate_latency)
            conv_unit_usec(latency, sizeof(latency), peakrate_latency);
        else
            conv_unit_usec(latency, sizeof(latency), rate_latency);

        *mp = add_log(msg, *mp, "latency=%s ", latency);
    }

    return(0);
}

/*
 * debug tbf options
 */
void debug_tca_options_tbf(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *tbf[__TCA_TBF_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(tbf, TCA_TBF_MAX, tca);

    if(tbf[TCA_TBF_PARMS])
        debug_tca_tbf_parms(lev+1, tbf[TCA_TBF_PARMS],
            "TCA_TBF_PARMS");

    if(tbf[TCA_TBF_RTAB])
        debug_rta_ignore(lev+1, tbf[TCA_TBF_RTAB],
            "TCA_TBF_RTAB");

    if(tbf[TCA_TBF_PTAB])
        debug_rta_ignore(lev+1, tbf[TCA_TBF_PTAB],
            "TCA_TBF_PTAB");
}

/*
 * debug attribute TCA_TBF_PARMS
 */
void debug_tca_tbf_parms(int lev, struct rtattr *tbf, const char *name)
{
    struct tc_tbf_qopt *qopt;
    struct tc_ratespec *rate;
    struct tc_ratespec *peak;

    if(debug_rta_len_chk(lev, tbf, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_tbf_qopt *)RTA_DATA(tbf);
    rate = &(qopt->rate);
    peak = &(qopt->peakrate);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tbf->rta_len));
    rec_dbg(lev, "    [ tc_tbf_qopt(%d) ]", sizeof(*qopt));

    debug_tc_ratespec(lev+2, rate, "rate");
    debug_tc_ratespec(lev+2, peak, "peakrate");

    rec_dbg(lev, "        limit(%d): %u", sizeof(qopt->limit), qopt->limit);
    rec_dbg(lev, "        buffer(%d): %u", sizeof(qopt->buffer), qopt->buffer);
    rec_dbg(lev, "        mtu(%d): %u", sizeof(qopt->mtu), qopt->mtu);
}
