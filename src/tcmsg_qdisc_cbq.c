/*
 * tcmsg_qdisc_cbq.c - traffic control qdisc message parser
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

#if HAVE_DECL_TCA_CBQ_UNSPEC
static double us2tick = 1;

/*
 * parse cbq options
 */
int parse_tca_options_cbq(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *cbq[__TCA_CBQ_MAX];
    struct tc_ratespec *rspec = NULL;
    struct tc_cbq_lssopt *lss = NULL;
    struct tc_cbq_wrropt *wrr = NULL;
    struct tc_cbq_fopt *fopt = NULL;
    struct tc_cbq_ovl *ovl = NULL;

    parse_nested_rtattr(cbq, TCA_CBQ_MAX, tca);

    if(cbq[TCA_CBQ_LSSOPT]) {
        if(RTA_PAYLOAD(cbq[TCA_CBQ_LSSOPT]) < sizeof(*lss)) {
            rec_log("error: %s: TCA_CBQ_LSSOPT: payload too short", __func__);
            return(1);
        }
        lss = (struct tc_cbq_lssopt *)RTA_DATA(cbq[TCA_CBQ_LSSOPT]);
    }

    if(cbq[TCA_CBQ_WRROPT]) {
        if(RTA_PAYLOAD(cbq[TCA_CBQ_WRROPT]) < sizeof(*wrr)) {
            rec_log("error: %s: TCA_CBQ_WRROPT: payload too short", __func__);
            return(1);
        }
        wrr = (struct tc_cbq_wrropt *)RTA_DATA(cbq[TCA_CBQ_WRROPT]);
    }

    if(cbq[TCA_CBQ_FOPT]) {
        if(RTA_PAYLOAD(cbq[TCA_CBQ_FOPT]) < sizeof(*fopt)) {
            rec_log("error: %s: TCA_CBQ_FOPT: payload too short", __func__);
            return(1);
        }
        fopt = (struct tc_cbq_fopt *)RTA_DATA(cbq[TCA_CBQ_FOPT]);
    }

    if(cbq[TCA_CBQ_OVL_STRATEGY]) {
        if(RTA_PAYLOAD(cbq[TCA_CBQ_OVL_STRATEGY]) < sizeof(*ovl)) {
            rec_log("error: %s: TCA_CBQ_OVL_STRATEGY: payload too short", __func__);
            return(1);
        }
        ovl = (struct tc_cbq_ovl *)RTA_DATA(cbq[TCA_CBQ_OVL_STRATEGY]);
    }

    if(cbq[TCA_CBQ_RATE]) {
        if(RTA_PAYLOAD(cbq[TCA_CBQ_RATE]) < sizeof(*rspec)) {
            rec_log("error: %s: TCA_CBQ_RATE: payload too short", __func__);
            return(1);
        }
        rspec = (struct tc_ratespec *)RTA_DATA(cbq[TCA_CBQ_RATE]);
    }

    if(rspec) {
        char rate[MAX_STR_SIZE];

        conv_unit_rate(rate, sizeof(rate), rspec->rate);
        *mp = add_log(msg, *mp, "rate=%s ", rate);
    }

    if(lss) {
        char maxidle[MAX_STR_SIZE];
        char minidle[MAX_STR_SIZE];

        get_us2tick();
        conv_unit_usec(maxidle, sizeof(maxidle),
            (lss->maxidle >> lss->ewma_log) / us2tick);
        *mp = add_log(msg, *mp, "maxidle=%s ", maxidle);

        if(lss->minidle != 0x7fffffff) {
            conv_unit_usec(minidle, sizeof(minidle),
                (lss->minidle >> lss->ewma_log) / us2tick);
            *mp = add_log(msg, *mp, "minidle=%s ", minidle);
        }

        *mp = add_log(msg, *mp, "level=%u avpkt=%u(byte) ", lss->level, lss->avpkt);
    }

    if(wrr) {
        if(wrr->priority != TC_CBQ_MAXPRIO)
            *mp = add_log(msg, *mp, "prio=%u ", wrr->priority);
        else
            *mp = add_log(msg, *mp, "prio=%u(no-transmit) ", wrr->priority);
    }

    return(0);
}

/*
 * debug cbq options
 */
void debug_tca_options_cbq(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *cbq[__TCA_CBQ_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len)); 
    parse_nested_rtattr(cbq, TCA_CBQ_MAX, tca);

    if(cbq[TCA_CBQ_LSSOPT])
        debug_tca_cbq_lssopt(lev+1, cbq[TCA_CBQ_LSSOPT],
            "TCA_CBQ_LSSOPT");

    if(cbq[TCA_CBQ_WRROPT])
        debug_tca_cbq_wrropt(lev+1, cbq[TCA_CBQ_WRROPT],
            "TCA_CBQ_WRROPT");

    if(cbq[TCA_CBQ_FOPT])
        debug_tca_cbq_fopt(lev+1, cbq[TCA_CBQ_FOPT],
            "TCA_CBQ_FOPT");

    if(cbq[TCA_CBQ_OVL_STRATEGY])
        debug_tca_cbq_ovl_strategy(lev+1, cbq[TCA_CBQ_OVL_STRATEGY],
            "TCA_CBQ_OVL_STRATEGY");

    if(cbq[TCA_CBQ_RATE])
        debug_tca_cbq_rate(lev+1, cbq[TCA_CBQ_RATE],
            "TCA_CBQ_RATE");

    if(cbq[TCA_CBQ_RTAB])
        debug_rta_ignore(lev+1, cbq[TCA_CBQ_RTAB],
            "TCA_CBQ_RTAB");

    if(cbq[TCA_CBQ_POLICE])
        debug_tca_cbq_police(lev+1, cbq[TCA_CBQ_POLICE],
            "TCA_CBQ_POLICE");
}

/*
 * debug attribute TCA_CBQ_LSSOPT
 */
void debug_tca_cbq_lssopt(int lev, struct rtattr *cbq, const char *name)
{
    struct tc_cbq_lssopt *lss;
    char flags_list[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, cbq, name, sizeof(*lss)))
        return;

    lss = (struct tc_cbq_lssopt *)RTA_DATA(cbq);
    conv_tcf_cbq_lss_flags(lss->flags, flags_list, sizeof(flags_list));

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(cbq->rta_len));
    rec_dbg(lev, "    [ tc_cbq_lssopt(%d) ]", sizeof(*lss));
    rec_dbg(lev, "        change(%d): %d", sizeof(lss->change), lss->change);
    rec_dbg(lev, "        flags(%d): %d(%s)", sizeof(lss->flags), lss->flags, flags_list);
    rec_dbg(lev, "        ewma_log(%d): %d", sizeof(lss->ewma_log), lss->ewma_log);
    rec_dbg(lev, "        level(%d): %d", sizeof(lss->level), lss->level);
    rec_dbg(lev, "        maxidle(%d): %u", sizeof(lss->maxidle), lss->maxidle);
    rec_dbg(lev, "        minidle(%d): %u", sizeof(lss->minidle), lss->minidle);
    rec_dbg(lev, "        offtime(%d): %u", sizeof(lss->offtime), lss->offtime);
    rec_dbg(lev, "        avpkt(%d): %u", sizeof(lss->avpkt), lss->avpkt);
}

/*
 * debug attribute TCA_CBQ_WRROPT
 */
void debug_tca_cbq_wrropt(int lev, struct rtattr *cbq, const char *name)
{
    struct tc_cbq_wrropt *wrr;

    if(debug_rta_len_chk(lev, cbq, name, sizeof(*wrr)))
        return;

    wrr = (struct tc_cbq_wrropt *)RTA_DATA(cbq);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(cbq->rta_len));
    rec_dbg(lev, "    [ tc_cbq_wrropt(%d) ]", sizeof(*wrr));
    rec_dbg(lev, "        flags(%d): %d", sizeof(wrr->flags), wrr->flags);
    rec_dbg(lev, "        priority(%d): %d", sizeof(wrr->priority), wrr->priority);
    rec_dbg(lev, "        cpriority(%d): %d", sizeof(wrr->cpriority), wrr->cpriority);
    rec_dbg(lev, "        __reserved(%d): %d", sizeof(wrr->__reserved), wrr->__reserved);
    rec_dbg(lev, "        allot(%d): %u", sizeof(wrr->allot), wrr->allot);
    rec_dbg(lev, "        weight(%d): %u", sizeof(wrr->weight), wrr->weight);
}

/*
 * debug attribute TCA_CBQ_FOPT
 */
void debug_tca_cbq_fopt(int lev, struct rtattr *cbq, const char *name)
{
    struct tc_cbq_fopt *fopt;
    char split[MAX_STR_SIZE];

    if(debug_rta_len_chk(lev, cbq, name, sizeof(*fopt)))
        return;

    fopt = (struct tc_cbq_fopt *)RTA_DATA(cbq);
    parse_tc_handle(split, sizeof(split), fopt->split);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(cbq->rta_len));
    rec_dbg(lev, "    [ tc_cbq_fopt(%d) ]", sizeof(*fopt));
    rec_dbg(lev, "        split(%d): %x:%x(%s)",
        sizeof(fopt->split), TC_H_MAJ(fopt->split)>>16,
        TC_H_MIN(fopt->split), split);
    rec_dbg(lev, "        defmap(%d): 0x%x", sizeof(fopt->defmap), fopt->defmap);
    rec_dbg(lev, "        defchange(%d): 0x%x", sizeof(fopt->defchange), fopt->defchange);
}

/*
 * debug attribute TCA_CBQ_OVL_STRATEGY
 */
void debug_tca_cbq_ovl_strategy(int lev, struct rtattr *cbq, const char *name)
{
    struct tc_cbq_ovl *ovl;
    char strategy_list[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, cbq, name, sizeof(*ovl)))
        return;

    ovl = (struct tc_cbq_ovl *)RTA_DATA(cbq);
    conv_tc_cbq_ovl_strategy(ovl->strategy, strategy_list, sizeof(strategy_list));

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(cbq->rta_len));
    rec_dbg(lev, "    [ tc_cbq_ovl(%d) ]", sizeof(*ovl));
    rec_dbg(lev, "        strategy(%d): %d(%s)",
        sizeof(ovl->strategy), ovl->strategy, strategy_list);
    rec_dbg(lev, "        priority2(%d): %d", sizeof(ovl->priority2), ovl->priority2);
    rec_dbg(lev, "        pad(%d): %d", sizeof(ovl->pad), ovl->pad);
    rec_dbg(lev, "        penalty(%d): %u", sizeof(ovl->penalty), ovl->penalty);
}

/*
 * debug attribute TCA_CBQ_RATE
 */
void debug_tca_cbq_rate(int lev, struct rtattr *cbq, const char *name)
{
    struct tc_ratespec *spec;

    if(debug_rta_len_chk(lev, cbq, name, sizeof(*spec)))
        return;

    spec = (struct tc_ratespec *)RTA_DATA(cbq);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(cbq->rta_len));

    debug_tc_ratespec(lev+1, spec, "");
}

/*
 * debug attribute TCA_CBQ_POLICE
 */
void debug_tca_cbq_police(int lev, struct rtattr *cbq, const char *name)
{
    struct tc_cbq_police *qopt;

    if(debug_rta_len_chk(lev, cbq, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_cbq_police *)RTA_DATA(cbq);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(cbq->rta_len));
    rec_dbg(lev, "    [ tc_cbq_police(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        police(%d): %d", sizeof(qopt->police), qopt->police);
    rec_dbg(lev, "        __res1(%d): %d", sizeof(qopt->__res1), qopt->__res1);
    rec_dbg(lev, "        __res2(%d): %d", sizeof(qopt->__res2), qopt->__res2);
}

/*
 * debug tc_cbq_xstats
 */
void debug_tc_cbq_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_cbq_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_cbq_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_cbq_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        borrows(%d): %u", sizeof(xstats->borrows), xstats->borrows);
    rec_dbg(lev, "        overactions(%d): %u", sizeof(xstats->overactions), xstats->overactions);
    rec_dbg(lev, "        avgidle(%d): %d", sizeof(xstats->avgidle), xstats->avgidle);
    rec_dbg(lev, "        undertime(%d): %d", sizeof(xstats->undertime), xstats->undertime);
}

/*
 *  convert TCF_CBQ_LSS change from number to string
 */
void conv_tcf_cbq_lss_change(int change, char *change_list, int len)
{
    if(!change) {
        strncpy(change_list, "NONE", len);
        return;
    }
#define _TCF_CBQ_LSS_LEVEL(s) \
    if((change & TCF_CBQ_LSS_##s) && (len - strlen(change_list) - 1 > 0)) \
        (change &= ~TCF_CBQ_LSS_##s) ? \
            strncat(change_list, #s ",", len - strlen(change_list) -1) : \
            strncat(change_list, #s, len - strlen(change_list) - 1);
    _TCF_CBQ_LSS_LEVEL(FLAGS);
    _TCF_CBQ_LSS_LEVEL(EWMA);
    _TCF_CBQ_LSS_LEVEL(MAXIDLE);
    _TCF_CBQ_LSS_LEVEL(MINIDLE);
    _TCF_CBQ_LSS_LEVEL(OFFTIME);
    _TCF_CBQ_LSS_LEVEL(AVPKT);
#undef _TCF_CBQ_LSS_LEVEL
    if(!strlen(change_list))
        strncpy(change_list, "UNKNOWN", len);
}

/*
 *  convert TCF_CBQ_LSS flags from number to string
 */
void conv_tcf_cbq_lss_flags(int flags, char *flags_list, int len)
{
    if(!flags) {
        strncpy(flags_list, "NONE", len);
        return;
    }
#define _TCF_CBQ_LSS_FLAGS(s) \
    if((flags & TCF_CBQ_LSS_##s) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~TCF_CBQ_LSS_##s) ? \
            strncat(flags_list, #s ",", len - strlen(flags_list) - 1) : \
            strncat(flags_list, #s, len - strlen(flags_list) - 1);
    _TCF_CBQ_LSS_FLAGS(BOUNDED);
    _TCF_CBQ_LSS_FLAGS(ISOLATED);
#undef _TCF_CBQ_LSS_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, "UNKNOWN", len);
}

/*
 *  convert TCF_CBQ_OVL strategy from number to string
 */
void conv_tc_cbq_ovl_strategy(int strategy, char *strategy_list, int len)
{
    if(!strategy) {
        strncpy(strategy_list, "NONE", len);
        return;
    }
#define _TC_CBQ_OVL_STRATEGY(s) \
    if((strategy & TC_CBQ_OVL_##s) && (len - strlen(strategy_list) - 1 > 0)) \
        (strategy &= ~TC_CBQ_OVL_##s) ? \
            strncat(strategy_list, #s ",", len - strlen(strategy_list) - 1) : \
            strncat(strategy_list, #s, len - strlen(strategy_list) - 1);
    _TC_CBQ_OVL_STRATEGY(CLASSIC);
    _TC_CBQ_OVL_STRATEGY(DELAY);
    _TC_CBQ_OVL_STRATEGY(LOWPRIO);
    _TC_CBQ_OVL_STRATEGY(DROP);
    _TC_CBQ_OVL_STRATEGY(RCLASSIC);
#undef _TC_CBQ_OVL_STRATEGY
    if(!strlen(strategy_list))
        strncpy(strategy_list, "UNKNOWN", len);
}
#endif
