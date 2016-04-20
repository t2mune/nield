/*
 * tcmsg_qdisc_netem.c - traffic control qdisc message parser
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

static double us2tick = 1;

/*
 * parse netem options
 */
int parse_tca_options_netem(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *netem[__TCA_NETEM_MAX];
    struct tc_netem_qopt *qopt;
    struct tc_netem_corr *corr = NULL;
    struct tc_netem_reorder *reorder = NULL;
    struct tc_netem_corrupt *corrupt = NULL;
    const double max_percent_value = 0xffffffff;

    if(RTA_PAYLOAD(tca) < sizeof(*qopt)) {
        rec_log("error: %s: TCA_OPTIONS: payload too short", __func__);
        return(1);
    }
    qopt = (struct tc_netem_qopt *)RTA_DATA(tca);

    parse_rtattr(netem, TCA_NETEM_MAX,
        RTA_DATA(tca) + sizeof(struct tc_netem_qopt),
        RTA_PAYLOAD(tca) - sizeof(struct tc_netem_qopt));

    if(netem[TCA_NETEM_CORR]) {
        if(RTA_PAYLOAD(netem[TCA_NETEM_CORR]) < sizeof(*corr)) {
            rec_log("error: %s: TCA_NETEM_CORR: payload too short", __func__);
            return(1);
        }
        corr = (struct tc_netem_corr *)RTA_DATA(netem[TCA_NETEM_CORR]);
    }

    if(netem[TCA_NETEM_REORDER]) {
        if(RTA_PAYLOAD(netem[TCA_NETEM_REORDER]) < sizeof(*reorder)) {
            rec_log("error: %s: TCA_NETEM_REORDER: payload too short", __func__);
            return(1);
        }
        reorder = (struct tc_netem_reorder *)RTA_DATA(netem[TCA_NETEM_REORDER]);
    }

    if(netem[TCA_NETEM_CORRUPT]) {
        if(RTA_PAYLOAD(netem[TCA_NETEM_REORDER]) < sizeof(*corrupt)) {
            rec_log("error: %s: TCA_NETEM_REORDER: payload too short", __func__);
            return(1);
        }
        corrupt = (struct tc_netem_corrupt *)RTA_DATA(netem[TCA_NETEM_CORRUPT]);
    }

#if HAVE_DECL_TCA_NETEM_LOSS
    struct rtattr *loss[__NETEM_LOSS_MAX];
    struct tc_netem_gimodel *gimodel = NULL;
    struct tc_netem_gemodel *gemodel = NULL;

    if(netem[TCA_NETEM_LOSS]) {
        parse_nested_rtattr(loss, NETEM_LOSS_MAX, netem[TCA_NETEM_LOSS]);

        if(loss[NETEM_LOSS_GI]) {
            if(RTA_PAYLOAD(loss[NETEM_LOSS_GI]) < sizeof(*gimodel)) {
                rec_log("error: %s: NETEM_LOSS_GI: payload too short",
                    __func__);
                return(1);
            }
            gimodel = (struct tc_netem_gimodel *)RTA_DATA(loss[NETEM_LOSS_GI]);
        }

        if(loss[NETEM_LOSS_GE]) {
            if(RTA_PAYLOAD(loss[NETEM_LOSS_GE]) < sizeof(*gemodel)) {
                rec_log("error: %s: NETEM_LOSS_GE: payload too short",
                    __func__);
                return(1);
            }
            gemodel = (struct tc_netem_gemodel *)RTA_DATA(loss[NETEM_LOSS_GE]);
        }
    }
#endif

#if HAVE_DECL_TCA_NETEM_RATE
    struct tc_netem_rate *rate = NULL;

    if(netem[TCA_NETEM_RATE]) {

        if(RTA_PAYLOAD(netem[TCA_NETEM_RATE]) < sizeof(*rate)) {
            rec_log("error: %s: TCA_NETEM_RATE: payload too short", __func__);
            return(1);
        }
        rate = (struct tc_netem_rate *)RTA_DATA(netem[TCA_NETEM_RATE]);
    }
#endif

    if(qopt->limit)
        *mp = add_log(msg, *mp, "limit=%u(packet) ", qopt->limit);

    if(qopt->latency) {
        char latency[MAX_STR_SIZE];

        get_us2tick();
        conv_unit_usec(latency, sizeof(latency), qopt->latency / us2tick);
        *mp = add_log(msg, *mp, "delay=%s ", latency);
        if(corr && corr->delay_corr)
            *mp = add_log(msg, *mp, "delay-correlation=%g(%%) ",
                (double)corr->delay_corr / max_percent_value * 100.);
    }

    if(qopt->jitter) {
        char jitter[MAX_STR_SIZE];

        get_us2tick();
        conv_unit_usec(jitter, sizeof(jitter), qopt->jitter / us2tick);
        *mp = add_log(msg, *mp, "jitter=%s ", jitter);
    }

    if(qopt->loss) {
        *mp = add_log(msg, *mp, "loss=%g(%%) ",
            (double)qopt->loss / max_percent_value * 100.);
        if(corr && corr->loss_corr)
            *mp = add_log(msg, *mp, "loss-correlation=%g(%%) ",
                (double)corr->loss_corr / max_percent_value * 100.);
    }

#if HAVE_DECL_TCA_NETEM_LOSS
    if(gimodel)
        *mp = add_log(msg, *mp, "loss-state(p13/p31/p32/p23/p14)="
            "%g(%%)/%g(%%)/%g(%%)/%g(%%)/%g(%%) ",
            (double)gimodel->p13 / max_percent_value * 100.,
            (double)gimodel->p31 / max_percent_value * 100.,
            (double)gimodel->p32 / max_percent_value * 100.,
            (double)gimodel->p23 / max_percent_value * 100.,
            (double)gimodel->p14 / max_percent_value * 100.);

    if(gemodel)
        *mp = add_log(msg, *mp, "loss-gemodel(p/r/1-h/1-k)="
            "%g(%%)/%g(%%)/%g(%%)/%g(%%) ",
            (double)gemodel->p / max_percent_value * 100.,
            (double)gemodel->r / max_percent_value * 100.,
            (double)gemodel->h / max_percent_value * 100.,
            (double)gemodel->k1 / max_percent_value * 100.);
#endif

    if(qopt->duplicate) {
        *mp = add_log(msg, *mp, "duplicate=%g(%%) ",
            (double)qopt->duplicate / max_percent_value * 100.);
        if(corr && corr->dup_corr)
            *mp = add_log(msg, *mp, "duplicate-correlation=%g(%%) ",
                (double)corr->dup_corr / max_percent_value * 100.);
    }

    if(reorder && reorder->probability) {
        *mp = add_log(msg, *mp, "reorder=%g(%%) ",
            (double)reorder->probability / max_percent_value * 100.);
        if(reorder->correlation)
            *mp = add_log(msg, *mp, "reorder-correlation=%g(%%) ",
                (double)reorder->correlation / max_percent_value * 100.);
    }

    if(corrupt && corrupt->probability) {
        *mp = add_log(msg, *mp, "corrupt=%g(%%) ",
            (double)corrupt->probability / max_percent_value * 100.);
        if(corrupt->correlation)
            *mp = add_log(msg, *mp, "corrupt-correlation=%g(%%) ",
                (double)corrupt->correlation / max_percent_value * 100.);
    }

#if HAVE_DECL_TCA_NETEM_RATE
    if(rate && rate->rate) {
        char netem_rate[MAX_STR_SIZE];

        conv_unit_rate(netem_rate, sizeof(netem_rate), rate->rate);
        *mp = add_log(msg, *mp, "rate=%s ", netem_rate);
                if(rate->packet_overhead)
            *mp = add_log(msg, *mp, "packet-overhead=%u(byte) ", rate->packet_overhead);

                if(rate->cell_size)
            *mp = add_log(msg, *mp, "cell-size=%u(byte) ", rate->cell_size);

                if(rate->cell_overhead)
            *mp = add_log(msg, *mp, "cell-overhead=%u(byte) ", rate->cell_overhead);
    }
#endif

    if(qopt->gap)
        *mp = add_log(msg, *mp, "gap=%u(packet) ", qopt->gap);

#if HAVE_DECL_TCA_NETEM_ECN
    if(netem[TCA_NETEM_ECN] && *(unsigned *)RTA_DATA(netem[TCA_NETEM_ECN]))
        *mp = add_log(msg, *mp, "ecn=on ");
#endif

    return(0);
}

/*
 * debug netem options
 */
void debug_tca_options_netem(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *netem[__TCA_NETEM_MAX];
    struct tc_netem_qopt *qopt;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_netem_qopt *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_netem_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        latency(%d): %u", sizeof(qopt->latency), qopt->latency);
    rec_dbg(lev, "        limit(%d): %u", sizeof(qopt->limit), qopt->limit);
    rec_dbg(lev, "        loss(%d): %u", sizeof(qopt->loss), qopt->loss);
    rec_dbg(lev, "        gap(%d): %u", sizeof(qopt->gap), qopt->gap);
    rec_dbg(lev, "        duplicate(%d): %u", sizeof(qopt->duplicate), qopt->duplicate);
    rec_dbg(lev, "        jitter(%d): %u", sizeof(qopt->jitter), qopt->jitter);

    parse_rtattr(netem, TCA_NETEM_MAX,
        RTA_DATA(tca) + sizeof(struct tc_netem_qopt),
        RTA_PAYLOAD(tca) - sizeof(struct tc_netem_qopt));

    if(netem[TCA_NETEM_CORR])
        debug_tca_netem_corr(lev+1, netem[TCA_NETEM_CORR],
            "TCA_NETEM_CORR");

    if(netem[TCA_NETEM_DELAY_DIST])
        debug_rta_ignore(lev+1, netem[TCA_NETEM_DELAY_DIST],
            "TCA_NETEM_DELAY_DIST");

    if(netem[TCA_NETEM_REORDER])
        debug_tca_netem_reorder(lev+1, netem[TCA_NETEM_REORDER],
            "TCA_NETEM_REORDER");

    if(netem[TCA_NETEM_CORRUPT])
        debug_tca_netem_corrupt(lev+1, netem[TCA_NETEM_CORRUPT],
            "TCA_NETEM_CORRUPT");

#if HAVE_DECL_TCA_NETEM_LOSS
    if(netem[TCA_NETEM_LOSS])
        debug_tca_netem_loss(lev+1, netem[TCA_NETEM_LOSS],
            "TCA_NETEM_LOSS");
#endif

#if HAVE_DECL_TCA_NETEM_RATE
    if(netem[TCA_NETEM_RATE])
        debug_tca_netem_rate(lev+1, netem[TCA_NETEM_RATE],
            "TCA_NETEM_RATE");
#endif

#if HAVE_DECL_TCA_NETEM_ECN
    if(netem[TCA_NETEM_ECN])
        debug_rta_u32(lev+1, netem[TCA_NETEM_ECN],
            "TCA_NETEM_ECN", NULL);
#endif
}

/*
 * debug attribute TCA_NETEM_CORR
 */
void debug_tca_netem_corr(int lev, struct rtattr *netem, const char *name)
{
    struct tc_netem_corr *corr;

    if(debug_rta_len_chk(lev, netem, name, sizeof(*corr)))
        return;

    corr = (struct tc_netem_corr *)RTA_DATA(netem);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(netem->rta_len));
    rec_dbg(lev, "    [ tc_netem_corr(%d) ]", sizeof(*corr));
    rec_dbg(lev, "        delay_corr(%d): %u", sizeof(corr->delay_corr), corr->delay_corr);
    rec_dbg(lev, "        loss_corr(%d): %u", sizeof(corr->loss_corr), corr->loss_corr);
    rec_dbg(lev, "        dup_corr(%d): %u", sizeof(corr->dup_corr), corr->dup_corr);
}

/*
 * debug attribute TCA_NETEM_REORDER
 */
void debug_tca_netem_reorder(int lev, struct rtattr *netem, const char *name)
{
    struct tc_netem_reorder *reorder;

    if(debug_rta_len_chk(lev, netem, name, sizeof(*reorder)))
        return;

    reorder = (struct tc_netem_reorder *)RTA_DATA(netem);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(netem->rta_len));
    rec_dbg(lev, "    [ tc_netem_reorder(%d) ]", sizeof(*reorder));
    rec_dbg(lev, "        probability(%d): %u",
        sizeof(reorder->probability), reorder->probability);
    rec_dbg(lev, "        correlation(%d): %u",
        sizeof(reorder->correlation), reorder->correlation);
}

/*
 * debug attribute TCA_NETEM_CORRUPT
 */
void debug_tca_netem_corrupt(int lev, struct rtattr *netem, const char *name)
{
    struct tc_netem_corrupt *corrupt;

    if(debug_rta_len_chk(lev, netem, name, sizeof(*corrupt)))
        return;

    corrupt = (struct tc_netem_corrupt *)RTA_DATA(netem);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(netem->rta_len));
    rec_dbg(lev, "    [ tc_netem_corrupt(%d) ]", sizeof(*corrupt));
    rec_dbg(lev, "        probability(%d): %u",
        sizeof(corrupt->probability), corrupt->probability);
    rec_dbg(lev, "        correlation(%d): %u",
        sizeof(corrupt->correlation), corrupt->correlation);
}

#if HAVE_DECL_TCA_NETEM_LOSS
/*
 * debug attribute TCA_NETEM_LOSS
 */
void debug_tca_netem_loss(int lev, struct rtattr *netem, const char *name)
{
    struct rtattr *loss[__NETEM_LOSS_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(netem->rta_len));

    parse_nested_rtattr(loss, NETEM_LOSS_MAX, netem);

    if(loss[NETEM_LOSS_GI])
        debug_netem_loss_gi(lev+1, loss[NETEM_LOSS_GI],
            "NETEM_LOSS_GI");

    if(loss[NETEM_LOSS_GE])
        debug_netem_loss_ge(lev+1, loss[NETEM_LOSS_GE],
            "NETEM_LOSS_GE");
}

/*
 * debug attribute NETEM_LOSS_GI
 */
void debug_netem_loss_gi(int lev, struct rtattr *loss, const char *name)
{
    struct tc_netem_gimodel *gi;

    if(debug_rta_len_chk(lev, loss, name, sizeof(*gi)))
        return;

    gi = (struct tc_netem_gimodel *)RTA_DATA(loss);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(loss->rta_len));
    rec_dbg(lev, "    [ tc_netem_gimodel(%d) ]", sizeof(*gi));
    rec_dbg(lev, "        p13(%d): %u", sizeof(gi->p13), gi->p13);
    rec_dbg(lev, "        p31(%d): %u", sizeof(gi->p31), gi->p31);
    rec_dbg(lev, "        p32(%d): %u", sizeof(gi->p32), gi->p32);
    rec_dbg(lev, "        p14(%d): %u", sizeof(gi->p14), gi->p14);
    rec_dbg(lev, "        p23(%d): %u", sizeof(gi->p23), gi->p23);
}

/*
 * debug attribute NETEM_LOSS_GE
 */
void debug_netem_loss_ge(int lev, struct rtattr *loss, const char *name)
{
    struct tc_netem_gemodel *ge;

    if(debug_rta_len_chk(lev, loss, name, sizeof(*ge)))
        return;

    ge = (struct tc_netem_gemodel *)RTA_DATA(loss);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(loss->rta_len));
    rec_dbg(lev, "    [ tc_netem_gemodel(%d) ]", sizeof(*ge));
    rec_dbg(lev, "        p(%d): %u", sizeof(ge->p), ge->p);
    rec_dbg(lev, "        r(%d): %u", sizeof(ge->r), ge->r);
    rec_dbg(lev, "        h(%d): %u", sizeof(ge->h), ge->h);
    rec_dbg(lev, "        k1(%d): %u", sizeof(ge->k1), ge->k1);
}
#endif

#if HAVE_DECL_TCA_NETEM_RATE
/*
 * debug attribute TCA_NETEM_RATE
 */
void debug_tca_netem_rate(int lev, struct rtattr *netem, const char *name)
{
    struct tc_netem_rate *rate;

    if(debug_rta_len_chk(lev, netem, name, sizeof(*rate)))
        return;

    rate = (struct tc_netem_rate *)RTA_DATA(netem);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(netem->rta_len));
    rec_dbg(lev, "    [ tc_netem_rate(%d) ]", sizeof(*rate));
    rec_dbg(lev, "        rate(%d): %u", sizeof(rate->rate), rate->rate);
    rec_dbg(lev, "        packet_overhead(%d): %u",
        sizeof(rate->packet_overhead), rate->packet_overhead);
    rec_dbg(lev, "        cell_size(%d): %u", sizeof(rate->cell_size), rate->cell_size);
    rec_dbg(lev, "        cell_overhead(%d): %u",
        sizeof(rate->cell_overhead), rate->cell_overhead);
}
#endif
