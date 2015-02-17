/*
 * tcmsg_qdisc.c - traffic control qdisc message parser
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

#define TIME_UNITS_PER_SEC 1000000

static double us2tick = 1;
static double clock_factor = 1;

/*
 * parse traffic control qdisc messages
 */
int parse_tcmsg_qdisc(struct nlmsghdr *nlh)
{
    struct tcmsg *tcm;
    int tcm_len;
    struct rtattr *tca[__TCA_MAX];
    char msg[MAX_MSG_SIZE] = "";
    char *mp = msg;
    char ifname[IFNAMSIZ];
    char parent[MAX_STR_SIZE] = "";
    char handle[MAX_STR_SIZE] = "";
    char kind[IFNAMSIZ] = "(unknown)";
    int log_opts = get_log_opts();

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get tcmsg */
    tcm_len = NLMSG_PAYLOAD(nlh, 0);
    if(tcm_len < sizeof(*tcm)) {
        rec_log("error: %s: tcmsg: length too short", __func__);
        return(1);
    }
    tcm = (struct tcmsg *)NLMSG_DATA(nlh);

    /* parse traffic control message attributes */
    parse_tc(tca, nlh);

    /* debug tcmsg */
    if(log_opts & L_DEBUG)
        debug_tcmsg(0, nlh, tcm, tca, tcm_len);

    /* kind of message */
    switch(nlh->nlmsg_type) {
        case RTM_NEWQDISC:
            mp = add_log(msg, mp, "tc qdisc added: ");
            break;
        case RTM_DELQDISC:
            mp = add_log(msg, mp, "tc qdisc deleted: ");
            break;
        case RTM_NEWTCLASS:
            mp = add_log(msg, mp, "tc class added: ");
            break;
        case RTM_DELTCLASS:
            mp = add_log(msg, mp, "tc class deleted: ");
            break;
        default:
            rec_log("error: %s: nlmsg_type: unknown message", __func__);
            return(1);
    }

    /* get interface name */
    if_indextoname_from_lists(tcm->tcm_ifindex, ifname);

    mp = add_log(msg, mp, "interface=%s ", ifname); 

    /* get parent qdisc handle */
    parse_tc_handle(parent, sizeof(parent), tcm->tcm_parent);
    mp = add_log(msg, mp, "parent=%s ", parent);

    /* get qdisc handle */
    parse_tc_handle(handle, sizeof(handle), tcm->tcm_handle);
    mp = add_log(msg, mp, "classid=%s ", handle);

    /* get qdisc kind */
    if(tca[TCA_KIND])
        strncpy(kind, (char *)RTA_DATA(tca[TCA_KIND]), sizeof(kind));

    mp = add_log(msg, mp, "qdisc=%s ", kind);

    /* get qdisc options */
    if(tca[TCA_OPTIONS]) {
        if(!strncmp(kind, "pfifo_fast", sizeof(kind))) {
            if(parse_tca_options_prio(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "pfifo", sizeof(kind))) {
            if(parse_tca_options_pfifo(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "bfifo", sizeof(kind))) {
            if(parse_tca_options_bfifo(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "prio", sizeof(kind))) {
            if(parse_tca_options_prio(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#ifdef HAVE_STRUCT_TC_MULTIQ_QOPT_BANDS
        } else if(!strncmp(kind, "multiq", sizeof(kind))) {
            if(parse_tca_options_multiq(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
#ifdef HAVE_STRUCT_TC_PLUG_QOPT_ACTION
        } else if(!strncmp(kind, "plug", sizeof(kind))) {
            if(parse_tca_options_plug(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
        } else if(!strncmp(kind, "sfq", sizeof(kind))) {
            if(parse_tca_options_sfq(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "tbf", sizeof(kind))) {
            if(parse_tca_options_tbf(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "red", sizeof(kind))) {
            if(parse_tca_options_red(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "gred", sizeof(kind))) {
            if(parse_tca_options_gred(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#if HAVE_DECL_TCA_CHOKE_UNSPEC
        } else if(!strncmp(kind, "choke", sizeof(kind))) {
            if(parse_tca_options_choke(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
        } else if(!strncmp(kind, "htb", sizeof(kind))) {
            if(parse_tca_options_htb(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "hfsc", sizeof(kind))) {
            if(parse_tca_options_hfsc(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "cbq", sizeof(kind))) {
            if(parse_tca_options_cbq(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "dsmark", sizeof(kind))) {
            if(parse_tca_options_dsmark(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
        } else if(!strncmp(kind, "netem", sizeof(kind))) {
            if(parse_tca_options_netem(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#if HAVE_DECL_TCA_DRR_UNSPEC
        } else if(!strncmp(kind, "drr", sizeof(kind))) {
            if(parse_tca_options_drr(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
#if HAVE_DECL_TCA_SFB_UNSPEC
        } else if(!strncmp(kind, "sfb", sizeof(kind))) {
            if(parse_tca_options_sfb(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
#if HAVE_DECL_TCA_QFQ_UNSPEC
        } else if(!strncmp(kind, "qfq", sizeof(kind))) {
            if(parse_tca_options_qfq(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
#if HAVE_DECL_TCA_CODEL_UNSPEC
        } else if(!strncmp(kind, "codel", sizeof(kind))) {
            if(parse_tca_options_codel(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
#if HAVE_DECL_TCA_FQ_CODEL_UNSPEC
        } else if(!strncmp(kind, "fq_codel", sizeof(kind))) {
            if(parse_tca_options_fq_codel(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
#endif
        }
    }

    /* write log */
    rec_log("%s", msg);

    return(0);
}

/*
 * convert unit data rate
 */
void conv_unit_rate(char *str, int len, double num)
{
    num *= 8.0;

    if(num >= 1000.0 * 1000.0 * 1000.0)
        snprintf(str, len, "%.3f(Gbit/s)", num / (1000.0 * 1000.0 * 1000.0));
    else if(num >= 1000.0 * 1000.0)
        snprintf(str, len, "%.3f(Mbit/s)", num / (1000.0 * 1000.0));
    else if(num >= 1000.0)
        snprintf(str, len, "%.3f(kbit/s)", num / 1000.0);
    else
        snprintf(str, len, "%.3f(bit/s)", num);
}

/*
 * convert unit data size
 */
void conv_unit_size(char *str, int len, double num)
{
    if(num >= 1024.0 * 1024.0 * 1024.0)
        snprintf(str, len, "%.3f(Gbyte)", num / (1024.0 * 1024.0 * 1024.0));
    else if(num >= 1024.0 * 1024.0)
        snprintf(str, len, "%.3f(Mbyte)", num / (1024.0 * 1024.0));
    else if(num >= 1024.0)
        snprintf(str, len, "%.3f(Kbyte)", num / 1024.0);
    else
        snprintf(str, len, "%.3f(byte)", num);
}

/*
 * convert unit of time
 */
void conv_unit_usec(char *str, int len, double usec)
{
    if(usec >= 1000.0 * 1000.0)
        snprintf(str, len, "%.3f(s)", usec / (1000.0 * 1000.0));
    else if(usec >= 1000.0)
        snprintf(str, len, "%.3f(ms)", usec / 1000.0);
    else if(usec < 0)
        snprintf(str, len, "%.3f(us)", 0.0);
    else
        snprintf(str, len, "%.3f(us)", usec);
}

/*
 * get ticks per usec
 */
int get_us2tick(void)
{
    FILE *fp;
    __u32 clock_res;
    __u32 us2ns;
    __u32 tick2ns;

    fp = fopen("/proc/net/psched", "r");
    if(fp == NULL)
        return -1;

    if(fscanf(fp, "%08x%08x%08x", &us2ns, &tick2ns, &clock_res) != 3) {
        fclose(fp);
        return(-1);
    }

    fclose(fp);

    if(clock_res == 1000000000)
        us2ns = tick2ns;

    clock_factor  = (double)clock_res / TIME_UNITS_PER_SEC;
    us2tick = (double)us2ns / tick2ns * clock_factor;

    return(0);
}

/*
 * get burst size
 *
 * (rate(byte/sec) * (buffer(tick) / us2tick(tick/usec))) / TIME_UNITS_PER_SEC(usec/sec)
 */
double get_burst_size(unsigned rate, unsigned buffer)
{
    return((double)rate * (buffer / us2tick)) / TIME_UNITS_PER_SEC;
}

/*
 * get latency
 */
double get_latency(unsigned rate, unsigned buffer, unsigned limit)
{
    return(TIME_UNITS_PER_SEC * (limit / (double)rate) - (buffer / us2tick));
}

/*
 * debug traffic control message
 */
void debug_tcmsg(int lev, struct nlmsghdr *nlh, struct tcmsg *tcm, struct rtattr *tca[], int tcm_len)
{
    /* debug tcmsg */
    char ifname[IFNAMSIZ] = "";
    char handle[MAX_STR_SIZE] = "";
    char parent[MAX_STR_SIZE] = "";
    char kind[IFNAMSIZ] = "";

    if_indextoname_from_lists(tcm->tcm_ifindex, ifname);

    switch(nlh->nlmsg_type) {
        case RTM_NEWQDISC:
        case RTM_DELQDISC:
        case RTM_NEWTCLASS:
        case RTM_DELTCLASS:
            parse_tc_handle(handle, sizeof(handle), tcm->tcm_handle);
            break;
        case RTM_NEWTFILTER:
        case RTM_DELTFILTER:
            parse_u32_handle(handle, sizeof(handle), tcm->tcm_handle);
            break;

    }
    parse_tc_handle(parent, sizeof(parent), tcm->tcm_parent);

    rec_dbg(lev, "*********************************************************************");

    rec_dbg(lev, "[ tcmsg(%d) ]",
        NLMSG_ALIGN(sizeof(*tcm)));
    rec_dbg(lev, "    tcm_family(%d): %d(%s)",
        sizeof(tcm->tcm_family), tcm->tcm_family,
        conv_af_type(tcm->tcm_family, 1));
    rec_dbg(lev, "    tcm__pad1(%d): %d",
        sizeof(tcm->tcm__pad1), tcm->tcm__pad1);
    rec_dbg(lev, "    tcm__pad2(%d): %d",
        sizeof(tcm->tcm__pad2), tcm->tcm__pad2);
    rec_dbg(lev, "    tcm_ifindex(%d): %d(%s)",
        sizeof(tcm->tcm_ifindex), tcm->tcm_ifindex, ifname);
    rec_dbg(lev, "    tcm_handle(%d): 0x%08x(%s)",
        sizeof(tcm->tcm_handle), tcm->tcm_handle, handle);
    rec_dbg(lev, "    tcm_parent(%d): 0x%08x(%s)",
        sizeof(tcm->tcm_parent), tcm->tcm_parent, parent);
    rec_dbg(lev, "    tcm_info(%d): 0x%08x(%u, %s)",
        sizeof(tcm->tcm_info), tcm->tcm_info,
        TC_H_MAJ(tcm->tcm_info)>>16,
        conv_eth_p(ntohs(TC_H_MIN(tcm->tcm_info)), 1));

    /* debug traffic control attributes */
    rec_dbg(lev,"*********************************************************************");
    rec_dbg(lev, "[ tcmsg attributes(%d) ]",
            NLMSG_ALIGN(tcm_len - NLMSG_ALIGN(sizeof(*tcm))));

    if(tca[TCA_KIND])
        debug_rta_str(lev+1, tca[TCA_KIND],
            "TCA_KIND", kind, sizeof(kind));

    if(tca[TCA_OPTIONS])
        debug_tca_options(lev+1, tcm, tca[TCA_OPTIONS],
            "TCA_OPTIONS", kind, sizeof(kind));

    if(tca[TCA_STATS])
        debug_tca_stats(lev+1, tca[TCA_STATS],
            "TCA_STATS");

    if(tca[TCA_XSTATS])
        debug_tca_xstats(lev+1, tca[TCA_XSTATS],
            "TCA_XSTATS", kind, sizeof(kind));

    if(tca[TCA_RATE])
        debug_tca_rate(lev+1, tca[TCA_RATE],
            "TCA_RATE");

    if(tca[TCA_FCNT])
        debug_rta_u32x(lev+1, tca[TCA_FCNT],
            "TCA_FCNT", NULL);

    if(tca[TCA_STATS2])
        debug_tca_stats2(lev+1, tca[TCA_STATS2],
            "TCA_STATS2");

#if HAVE_DECL_TCA_STAB_UNSPEC
    if(tca[TCA_STAB])
        debug_tca_stab(lev+1, tca[TCA_STAB],
            "TCA_STAB");
#endif

    rec_dbg(lev, "");
}

/*
 * debug attribute TCA_OPTIONS
 */
void debug_tca_options(int lev, struct tcmsg *tcm, struct rtattr *tca,
    const char *name, char *kind, int len)
{
    /* kinds of qdisc */
    if(!strncmp(kind, "pfifo_fast", len))
        debug_tca_options_prio(lev, tca, name);
    else if(!strncmp(kind, "pfifo", len))
        debug_tca_options_fifo(lev, tca, name);
    else if(!strncmp(kind, "bfifo", len))
        debug_tca_options_fifo(lev, tca, name);
    else if(!strncmp(kind, "prio", len))
        debug_tca_options_prio(lev, tca, name);
#ifdef HAVE_STRUCT_TC_MULTIQ_QOPT_BANDS
    else if(!strncmp(kind, "multiq", len))
        debug_tca_options_multiq(lev, tca, name);
#endif
#ifdef HAVE_STRUCT_TC_PLUG_QOPT_ACTION
    else if(!strncmp(kind, "plug", len))
        debug_tca_options_plug(lev, tca, name);
#endif
    else if(!strncmp(kind, "sfq", len))
        debug_tca_options_sfq(lev, tca, name);
    else if(!strncmp(kind, "tbf", len))
        debug_tca_options_tbf(lev, tca, name);
    else if(!strncmp(kind, "red", len))
        debug_tca_options_red(lev, tca, name);
    else if(!strncmp(kind, "gred", len))
        debug_tca_options_gred(lev, tca, name);
#if HAVE_DECL_TCA_CHOKE_UNSPEC
    else if(!strncmp(kind, "choke", len))
        debug_tca_options_choke(lev, tca, name);
#endif
    else if(!strncmp(kind, "htb", len))
        debug_tca_options_htb(lev, tca, name);
    else if(!strncmp(kind, "hfsc", len))
        debug_tca_options_hfsc(lev, tca, name);
    else if(!strncmp(kind, "cbq", len))
        debug_tca_options_cbq(lev, tca, name);
    else if(!strncmp(kind, "dsmark", len))
        debug_tca_options_dsmark(lev, tca, name);
    else if(!strncmp(kind, "netem", len))
        debug_tca_options_netem(lev, tca, name);
#if HAVE_DECL_TCA_DRR_UNSPEC
    else if(!strncmp(kind, "drr", len))
        debug_tca_options_drr(lev, tca, name);
#endif
#if HAVE_DECL_TCA_SFB_UNSPEC
    else if(!strncmp(kind, "sfb", len))
        debug_tca_options_sfb(lev, tca, name);
#endif
#if HAVE_DECL_TCA_QFQ_UNSPEC
    else if(!strncmp(kind, "qfq", len))
        debug_tca_options_qfq(lev, tca, name);
#endif
#if HAVE_DECL_TCA_CODEL_UNSPEC
    else if(!strncmp(kind, "codel", len))
        debug_tca_options_codel(lev, tca, name);
#endif
#if HAVE_DECL_TCA_FQ_CODEL_UNSPEC
    else if(!strncmp(kind, "fq_codel", len))
        debug_tca_options_fq_codel(lev, tca, name);
#endif
    else if(!strncmp(kind, "ingress", len))
        return;
    /* kinds of filter */
    else if(!strncmp(kind, "u32", len))
        debug_tca_options_u32(lev, tca, name);
    else if(!strncmp(kind, "rsvp", len))
        debug_tca_options_rsvp(lev, tcm, tca, name);
    else if(!strncmp(kind, "route", len))
        debug_tca_options_route(lev, tca, name);
    else if(!strncmp(kind, "fw", len))
        debug_tca_options_fw(lev, tca, name);
    else if(!strncmp(kind, "tcindex", len))
        debug_tca_options_tcindex(lev, tca, name);
#if HAVE_DECL_TCA_FLOW_UNSPEC
    else if(!strncmp(kind, "flow", len))
        debug_tca_options_flow(lev, tca, name);
#endif
    else if(!strncmp(kind, "basic", len))
        debug_tca_options_basic(lev, tca, name);
#if HAVE_DECL_TCA_CGROUP_UNSPEC
    else if(!strncmp(kind, "cgroup", len))
        debug_tca_options_cgroup(lev, tca, name);
#endif
    else
        rec_dbg(lev, "%s(%hu): -- unknown option %s --",
            name, RTA_ALIGN(tca->rta_len), kind);
}
 
/*
 * debug attribute TCA_STATS
 */
void debug_tca_stats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_stats *stats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*stats)))
        return;

    stats = (struct tc_stats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_stats(%d) ]", sizeof(*stats));
    rec_dbg(lev, "        bytes(%d): %lu", sizeof(stats->bytes), stats->bytes);
    rec_dbg(lev, "        packets(%d): %u", sizeof(stats->packets), stats->packets);
    rec_dbg(lev, "        drops(%d): %u", sizeof(stats->drops), stats->drops);
    rec_dbg(lev, "        overlimits(%d): %u", sizeof(stats->overlimits), stats->overlimits);
    rec_dbg(lev, "        bps(%d): %u", sizeof(stats->bps), stats->bps);
    rec_dbg(lev, "        pps(%d): %u", sizeof(stats->pps), stats->pps);
    rec_dbg(lev, "        qlen(%d): %u", sizeof(stats->qlen), stats->qlen);
    rec_dbg(lev, "        backlog(%d): %u", sizeof(stats->backlog), stats->backlog);
}

/*
 * debug attribute TCA_XSTATS
 */
void debug_tca_xstats(int lev, struct rtattr *tca,
    const char *name, char *kind, int len)
{
    /* if(0) is dummy */
    if(0)
        return;
#ifdef HAVE_STRUCT_TC_SFQ_XSTATS_ALLOT
    else if(!strncmp(kind, "sfq", len))
        debug_tc_sfq_xstats(lev, tca, name);
#endif
    else if(!strncmp(kind, "red", len))
        debug_tc_red_xstats(lev, tca, name);
#if HAVE_DECL_TCA_CHOKE_UNSPEC
    else if(!strncmp(kind, "choke", len))
        debug_tc_choke_xstats(lev, tca, name);
#endif
    else if(!strncmp(kind, "htb", len))
        debug_tc_htb_xstats(lev, tca, name);
    else if(!strncmp(kind, "cbq", len))
        debug_tc_cbq_xstats(lev, tca, name);
#if HAVE_DECL_TCA_DRR_UNSPEC
    else if(!strncmp(kind, "drr", len))
        debug_tc_drr_xstats(lev, tca, name);
#endif
#if HAVE_DECL_TCA_SFB_UNSPEC
    else if(!strncmp(kind, "sfb", len))
        debug_tc_sfb_xstats(lev, tca, name);
#endif
#if HAVE_DECL_TCA_QFQ_UNSPEC
    else if(!strncmp(kind, "qfq", len))
        debug_tc_qfq_xstats(lev, tca, name);
#endif
#if HAVE_DECL_TCA_CODEL_UNSPEC
    else if(!strncmp(kind, "codel", len))
        debug_tc_codel_xstats(lev, tca, name);
#endif
#if HAVE_DECL_TCA_FQ_CODEL_UNSPEC
    else if(!strncmp(kind, "fq_codel", len))
        debug_tc_fq_codel_xstats(lev, tca, name);
#endif
    else if(!strncmp(kind, "ingress", len))
        return;
    else
        rec_dbg(lev, "%s(%hu): -- unknown kind %s --",
            name, RTA_ALIGN(tca->rta_len), kind);
}

/*
 * debug attribute TCA_RATE
 */
void debug_tca_rate(int lev, struct rtattr *tca, const char *name)
{
    struct tc_estimator *rate;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*rate)))
        return;

    rate = (struct tc_estimator *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_estimator(%d) ]", sizeof(*rate));
    rec_dbg(lev, "        interval(%d): %d", sizeof(rate->interval), rate->interval);
    rec_dbg(lev, "        ewma_log(%d): %d", sizeof(rate->ewma_log), rate->ewma_log);
}

/*
 * debug attribute TCA_STATS2
 */
void debug_tca_stats2(int lev, struct rtattr *tca, const char *name)
{
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));

    debug_tca_stats2_attr(lev, tca);
}

/*
 * debug attributes TCA_STATS_*
 */
void debug_tca_stats2_attr(int lev, struct rtattr *tca)
{
    struct rtattr *stats2[__TCA_STATS_MAX];

    parse_nested_rtattr(stats2, TCA_STATS_MAX, tca);

    if(stats2[TCA_STATS_BASIC])
        debug_tca_stats_basic(lev+1, stats2[TCA_STATS_BASIC],
            "TCA_STATS_BASIC");

    if(stats2[TCA_STATS_RATE_EST])
        debug_tca_stats_rate_est(lev+1, stats2[TCA_STATS_RATE_EST],
            "TCA_STATS_RATE_EST");

    if(stats2[TCA_STATS_QUEUE])
        debug_tca_stats_queue(lev+1, stats2[TCA_STATS_QUEUE],
            "TCA_STATS_QUEUE");

    if(stats2[TCA_STATS_APP])
        debug_tca_stats_app(lev, stats2[TCA_STATS_APP],
            "TCA_STATS_APP");
}

/*
 * debug attribute TCA_STATS_BASIC
 */
void debug_tca_stats_basic(int lev, struct rtattr *stats2, const char *name)
{
    struct gnet_stats_basic *basic;

    if(debug_rta_len_chk(lev, stats2, name, sizeof(*basic)))
        return;

    basic = (struct gnet_stats_basic *)RTA_DATA(stats2);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(stats2->rta_len));
    rec_dbg(lev, "    [ gnet_stats_basic(%d) ]", sizeof(*basic));
    rec_dbg(lev, "        bytes(%d): %lu", sizeof(basic->bytes), basic->bytes);
    rec_dbg(lev, "        packets(%d): %u", sizeof(basic->packets), basic->packets);
}

/*
 * debug attribute TCA_STATS_RATE_EST
 */
void debug_tca_stats_rate_est(int lev, struct rtattr *stats2, const char *name)
{
    struct gnet_stats_rate_est *rate;

    if(debug_rta_len_chk(lev, stats2, name, sizeof(*rate)))
        return;

    rate = (struct gnet_stats_rate_est *)RTA_DATA(stats2);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(stats2->rta_len));
    rec_dbg(lev, "    [ gnet_stats_rate_est(%d) ]", sizeof(*rate));
    rec_dbg(lev, "        bps(%d): %u", sizeof(rate->bps), rate->bps);
    rec_dbg(lev, "        pps(%d): %u", sizeof(rate->pps), rate->pps);
}

/*
 * debug attribute TCA_STATS_QUEUE
 */
void debug_tca_stats_queue(int lev, struct rtattr *stats2, const char *name)
{
    struct gnet_stats_queue *queue;

    if(debug_rta_len_chk(lev, stats2, name, sizeof(*queue)))
        return;

    queue = (struct gnet_stats_queue *)RTA_DATA(stats2);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(stats2->rta_len));
    rec_dbg(lev, "    [ gnet_stats_queue(%d) ]", sizeof(*queue));
    rec_dbg(lev, "        qlen(%d): %u", sizeof(queue->qlen), queue->qlen);
    rec_dbg(lev, "        backlog(%d): %u", sizeof(queue->backlog), queue->backlog);
    rec_dbg(lev, "        drops(%d): %u", sizeof(queue->drops), queue->drops);
    rec_dbg(lev, "        requeue(%d): %u", sizeof(queue->requeues), queue->requeues);
    rec_dbg(lev, "        overlimits(%d): %u", sizeof(queue->overlimits), queue->overlimits);
}

/*
 * debug attribute TCA_STATS_APP
 */
void debug_tca_stats_app(int lev, struct rtattr *stats2, const char *name)
{
    struct gnet_estimator *est;

    if(debug_rta_len_chk(lev, stats2, name, sizeof(*est)))
        return;

    est = (struct gnet_estimator *)RTA_DATA(stats2);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(stats2->rta_len));
    rec_dbg(lev, "    [ gnet_estimator(%d) ]", sizeof(*est));
    rec_dbg(lev, "        interval(%d): %d", sizeof(est->interval), est->interval);
    rec_dbg(lev, "        ewma_log(%d): %d", sizeof(est->ewma_log), est->ewma_log);
}

#if HAVE_DECL_TCA_STAB_UNSPEC
/*
 * debug attribute TCA_STAB
 */
void debug_tca_stab(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *stab[__TCA_STAB_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));

    parse_nested_rtattr(stab, TCA_STAB_MAX, tca);

    if(stab[TCA_STAB_BASE])
        debug_tca_stab_base(lev+1, stab[TCA_STAB_BASE],
            "TCA_STAB_BASE");

    if(stab[TCA_STAB_DATA])
        debug_rta_ignore(lev+1, stab[TCA_STAB_DATA],
            "TCA_STAB_DATA");
}


/*
 * debug attribute TCA_STAB_BASE
 */
void debug_tca_stab_base(int lev, struct rtattr *stab, const char *name)
{
    struct tc_sizespec *base;

    if(debug_rta_len_chk(lev, stab, name, sizeof(*base)))
        return;

    base = (struct tc_sizespec *)RTA_DATA(stab);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(stab->rta_len));
    rec_dbg(lev, "    [ tc_sizespec(%d) ]", sizeof(*base));
    rec_dbg(lev, "        cell_log(%d): %d", sizeof(base->cell_log), base->cell_log);
    rec_dbg(lev, "        size_log(%d): %d", sizeof(base->size_log), base->size_log);
    rec_dbg(lev, "        cell_align(%d): %hd", sizeof(base->cell_align), base->cell_align);
    rec_dbg(lev, "        overhead(%d): %d", sizeof(base->overhead), base->overhead);
    rec_dbg(lev, "        linklayer(%d): %u", sizeof(base->linklayer), base->linklayer);
    rec_dbg(lev, "        mpu(%d): %u", sizeof(base->mpu), base->mpu);
    rec_dbg(lev, "        mtu(%d): %u", sizeof(base->mtu), base->mtu);
    rec_dbg(lev, "        tsize(%d): %u", sizeof(base->tsize), base->tsize);
}
#endif

/*
 * debug struct tc_ratespec
 */
void debug_tc_ratespec(int lev, struct tc_ratespec *rate, char *name)
{
    rec_dbg(lev, "[ tc_ratespec %s(%d) ]", name, sizeof(*rate));
    rec_dbg(lev, "    cell_log(%d): %d", sizeof(rate->cell_log), rate->cell_log);
#ifdef HAVE_STRUCT_TC_RATESPEC___RESERVED
    rec_dbg(lev, "    __reserved(%d): %d", sizeof(rate->__reserved), rate->__reserved);
#endif
#ifdef HAVE_STRUCT_TC_RATESPEC_LINKLAYER
    rec_dbg(lev, "    linklayer(%d): %d", sizeof(rate->linklayer), rate->linklayer);
#endif
#ifdef HAVE_STRUCT_TC_RATESPEC_FEATURE
    rec_dbg(lev, "    feature(%d): %hu", sizeof(rate->feature), rate->feature);
#endif
#ifdef HAVE_STRUCT_TC_RATESPEC_OVERHEAD
    rec_dbg(lev, "    overhead(%d): %hu", sizeof(rate->overhead), rate->overhead);
#endif
#ifdef HAVE_STRUCT_TC_RATESPEC_ADDEND
    rec_dbg(lev, "    addend(%d): %hd", sizeof(rate->addend), rate->addend);
#endif
#ifdef HAVE_STRUCT_TC_RATESPEC_CELL_ALIGN
    rec_dbg(lev, "    cell_align(%d): %hd", sizeof(rate->cell_align), rate->cell_align);
#endif
    rec_dbg(lev, "    mpu(%d): %hu", sizeof(rate->mpu), rate->mpu);
    rec_dbg(lev, "    rate(%d): %u", sizeof(rate->rate), rate->rate);
}
