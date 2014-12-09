/*
 * tcmsg_qdisc_htb.c - traffic control qdisc message parser
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
 * parse htb options
 */
int parse_tca_options_htb(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *htb[__TCA_HTB_MAX];

    parse_nested_rtattr(htb, TCA_HTB_MAX, tca);

    if(htb[TCA_HTB_INIT]) {
        struct tc_htb_glob *glob;

        if(RTA_PAYLOAD(htb[TCA_HTB_INIT]) < sizeof(*glob)) {
            rec_log("error: %s: TCA_HTB_INIT: payload too short", __func__);
            return(1);
        }
        glob = (struct tc_htb_glob *)RTA_DATA(htb[TCA_HTB_INIT]);

        *mp = add_log(msg, *mp, "rate2quantum=%u ", glob->rate2quantum);
        *mp = add_log(msg, *mp, "default-class=0x%x ", glob->defcls);
    }

    if(htb[TCA_HTB_PARMS]) {
        struct tc_htb_opt *opt;
        char rate[MAX_STR_SIZE];
        char ceil[MAX_STR_SIZE];
        char burst[MAX_STR_SIZE];
        char cburst[MAX_STR_SIZE];

        if(RTA_PAYLOAD(htb[TCA_HTB_PARMS]) < sizeof(*opt)) {
            rec_log("error: %s: TCA_HTB_PARMS: payload too short", __func__);
            return(1);
        }
        opt = (struct tc_htb_opt *)RTA_DATA(htb[TCA_HTB_PARMS]);

        get_us2tick();
        conv_unit_rate(rate, sizeof(rate), opt->rate.rate);
        conv_unit_size(burst, sizeof(burst),
            get_burst_size(opt->rate.rate, opt->buffer));
        conv_unit_rate(ceil, sizeof(ceil), opt->ceil.rate);
        conv_unit_size(cburst, sizeof(cburst),
            get_burst_size(opt->ceil.rate, opt->cbuffer));

        *mp = add_log(msg, *mp, "rate=%s burst=%s ceil=%s cburst=%s level=%u prio=%u ",
            rate, burst, ceil, cburst, opt->level, opt->prio);
    }

    return(0);
}

/*
 * debug htb options
 */
void debug_tca_options_htb(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *htb[__TCA_HTB_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(htb, TCA_HTB_MAX, tca);

    if(htb[TCA_HTB_PARMS])
        debug_tca_htb_parms(lev+1, htb[TCA_HTB_PARMS],
            "TCA_HTB_PARMS");

    if(htb[TCA_HTB_INIT])
        debug_tca_htb_init(lev+1, htb[TCA_HTB_INIT],
            "TCA_HTB_INIT");

    if(htb[TCA_HTB_CTAB])
        debug_rta_ignore(lev+1, htb[TCA_HTB_CTAB],
            "TCA_HTB_CTAB");

    if(htb[TCA_HTB_RTAB])
        debug_rta_ignore(lev+1, htb[TCA_HTB_RTAB],
            "TCA_HTB_RTAB");
}

/*
 * debug attribute TCA_HTB_PARMS
 */
void debug_tca_htb_parms(int lev, struct rtattr *htb, const char *name)
{
    struct tc_htb_opt *opt;
    struct tc_ratespec *rate, *ceil;

    if(debug_rta_len_chk(lev, htb, name, sizeof(*opt)))
        return;

    opt = (struct tc_htb_opt *)RTA_DATA(htb);
    rate = &(opt->rate);
    ceil = &(opt->ceil);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(htb->rta_len));
    rec_dbg(lev, "    [ tc_htb_opt(%d) ]", sizeof(*opt));

    debug_tc_ratespec(lev+2, rate, "rate");
    debug_tc_ratespec(lev+2, ceil, "ceil");

    rec_dbg(lev, "        buffer(%d): %u", sizeof(opt->buffer), opt->buffer);
    rec_dbg(lev, "        cbuffer(%d): %u", sizeof(opt->cbuffer), opt->cbuffer);
    rec_dbg(lev, "        quantum(%d): %u", sizeof(opt->quantum), opt->quantum);
    rec_dbg(lev, "        level(%d): %u", sizeof(opt->level), opt->level);
    rec_dbg(lev, "        prio(%d): %u", sizeof(opt->prio), opt->prio);
}

/*
 * debug attribute TCA_HTB_INIT
 */
void debug_tca_htb_init(int lev, struct rtattr *htb, const char *name)
{
    struct tc_htb_glob *glob;

    if(debug_rta_len_chk(lev, htb, name, sizeof(*glob)))
        return;

    glob = (struct tc_htb_glob *)RTA_DATA(htb);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(htb->rta_len));
    rec_dbg(lev, "    [ tc_htb_glob(%d) ]", sizeof(*glob));
    rec_dbg(lev, "        version(%d): %u", sizeof(glob->version), glob->version);
    rec_dbg(lev, "        rate2quantum(%d): %u", sizeof(glob->rate2quantum), glob->rate2quantum);
    rec_dbg(lev, "        defcls(%d): 0x%x", sizeof(glob->defcls), glob->defcls);
    rec_dbg(lev, "        debug(%d): %u", sizeof(glob->debug), glob->debug);
    rec_dbg(lev, "        direct_pkts(%d): %u", sizeof(glob->direct_pkts), glob->direct_pkts);
}

/*
 * debug tc_htb_xstats
 */
void debug_tc_htb_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_htb_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_htb_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_htb_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        lends(%d): %u", sizeof(xstats->lends), xstats->lends);
    rec_dbg(lev, "        borrows(%d): %u", sizeof(xstats->borrows), xstats->borrows);
    rec_dbg(lev, "        giants(%d): %u", sizeof(xstats->giants), xstats->giants);
    rec_dbg(lev, "        tokens(%d): %u", sizeof(xstats->tokens), xstats->tokens);
    rec_dbg(lev, "        ctokens(%d): %u", sizeof(xstats->ctokens), xstats->ctokens);
}
