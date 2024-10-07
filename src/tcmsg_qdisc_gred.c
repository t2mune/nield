/*
 * tcmsg_qdisc_gred.c - traffic control qdisc message parser
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
 * parse gred options
 */
int parse_tca_options_gred(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *gred[__TCA_GRED_MAX];
    struct tc_gred_sopt *sopt = NULL;
    struct tc_gred_qopt *qopt = NULL;
    unsigned *max_p = NULL;
    int i, flag = 0;
    char *mp_tmp = *mp;
    char limit[MAX_STR_SIZE] = "";
    char min[MAX_STR_SIZE] = "";
    char max[MAX_STR_SIZE] = "";

    parse_nested_rtattr(gred, TCA_GRED_MAX, tca);

    if(gred[TCA_GRED_PARMS]) {
        if(RTA_PAYLOAD(gred[TCA_GRED_PARMS]) < sizeof(*qopt)) {
            rec_log("error: %s: TCA_GRED_PARMS: payload too short", __func__);
            return(1);
        }
        qopt = (struct tc_gred_qopt *)RTA_DATA(gred[TCA_GRED_PARMS]);
    }

    if(gred[TCA_GRED_DPS]) {
        if(RTA_PAYLOAD(gred[TCA_GRED_DPS]) < sizeof(*sopt)) {
            rec_log("error: %s: TCA_GRED_DPS: payload too short", __func__);
            return(1);
        }
        sopt = (struct tc_gred_sopt *)RTA_DATA(gred[TCA_GRED_DPS]);
    }

    if(!sopt || !qopt) {
        rec_log("%s", msg);
        return(0);
    }

#if HAVE_DECL_TCA_GRED_MAX_P
    if(gred[TCA_GRED_MAX_P]) {
        if(RTA_PAYLOAD(gred[TCA_GRED_MAX_P]) < sizeof(*max_p)) {
            rec_log("error: %s: TCA_GRED_MAX_P: payload too short", __func__);
            return(1);
        }
        max_p = (unsigned *)RTA_DATA(gred[TCA_GRED_MAX_P]);
    }
#endif

    for(i = 0; i < sopt->DPs; i++, qopt++) {
        if(qopt->DP >= sopt->DPs)
            continue;

        conv_unit_size(limit, sizeof(limit), qopt->limit);
        conv_unit_size(min, sizeof(min), qopt->qth_min);
        conv_unit_size(max, sizeof(max), qopt->qth_max);

        *mp = add_log(msg, *mp, "DP=%u limit=%s min=%s max=%s prio=%d ",
            qopt->DP, limit, min, max, qopt->prio);
        if(max_p)
            *mp = add_log(msg, *mp, "probability=%g(%%) ", max_p[i] / pow(2, 32) * 100);
        rec_log("%s", msg);
        *mp = mp_tmp;
        flag = 1;
    }

    if(!flag || strstr(msg, "qdisc deleted")) {
        *mp = add_log(msg, *mp, "DPs=%u default-DP=%u ", sopt->DPs, sopt->def_DP);
        rec_log("%s", msg);
    }

    return(0);
}

/*
 * debug gred options
 */
void debug_tca_options_gred(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *gred[__TCA_GRED_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(gred, TCA_GRED_MAX, tca);

    if(gred[TCA_GRED_PARMS])
        debug_tca_gred_parms(lev+1, gred[TCA_GRED_PARMS],
            "TCA_GRED_PARMS");

    if(gred[TCA_GRED_STAB])
        debug_rta_ignore(lev+1, gred[TCA_GRED_STAB],
            "TCA_GRED_STAB");

    if(gred[TCA_GRED_DPS])
        debug_tca_gred_dps(lev+1, gred[TCA_GRED_DPS],
            "TCA_GRED_DPS");

#if HAVE_DECL_TCA_GRED_MAX_P
    if(gred[TCA_GRED_MAX_P])
        debug_tca_gred_max_p(lev+1, gred[TCA_GRED_MAX_P],
            "TCA_GRED_MAX_P");
#endif
}

/*
 * debug attribute TCA_GRED_PARMS
 */
void debug_tca_gred_parms(int lev, struct rtattr *gred, const char *name)
{
    struct tc_gred_qopt *qopt;
    int i;

    if(debug_rta_len_chk(lev, gred, name, sizeof(*qopt) * MAX_DPs))
        return;

    qopt = (struct tc_gred_qopt *)RTA_DATA(gred);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(gred->rta_len));

    for(i = 0; i < MAX_DPs; i++, qopt++) {
        rec_dbg(lev, "    [ tc_gred_qopt(%hu) ]", sizeof(*qopt));
        rec_dbg(lev, "        limit(%d): %u", sizeof(qopt->limit), qopt->limit);
        rec_dbg(lev, "        qth_min(%d): %u", sizeof(qopt->qth_min), qopt->qth_min);
        rec_dbg(lev, "        qth_max(%d): %u", sizeof(qopt->qth_max), qopt->qth_max);
        rec_dbg(lev, "        DP(%d): %u", sizeof(qopt->DP), qopt->DP);
        rec_dbg(lev, "        backlog(%d): %u", sizeof(qopt->backlog), qopt->backlog);
        rec_dbg(lev, "        qave(%d): %u", sizeof(qopt->qave), qopt->qave);
        rec_dbg(lev, "        forced(%d): %u", sizeof(qopt->forced), qopt->forced);
        rec_dbg(lev, "        early(%d): %u", sizeof(qopt->early), qopt->early);
        rec_dbg(lev, "        other(%d): %u", sizeof(qopt->other), qopt->other);
        rec_dbg(lev, "        pdrop(%d): %u", sizeof(qopt->pdrop), qopt->pdrop);
        rec_dbg(lev, "        Wlog(%d): %d", sizeof(qopt->Wlog), qopt->Wlog);
        rec_dbg(lev, "        Plog(%d): %d", sizeof(qopt->Plog), qopt->Plog);
        rec_dbg(lev, "        Scell_log(%d): %d", sizeof(qopt->Scell_log), qopt->Scell_log);
        rec_dbg(lev, "        prio(%d): %d", sizeof(qopt->prio), qopt->prio);
        rec_dbg(lev, "        packets(%d): %u", sizeof(qopt->packets), qopt->packets);
        rec_dbg(lev, "        bytesin(%d): %u", sizeof(qopt->bytesin), qopt->bytesin);
    }
}

/*
 * debug attribute TCA_GRED_DPS
 */
void debug_tca_gred_dps(int lev, struct rtattr *gred, const char *name)
{
    struct tc_gred_sopt *sopt;

    if(debug_rta_len_chk(lev, gred, name, sizeof(*sopt)))
        return;

    sopt = (struct tc_gred_sopt *)RTA_DATA(gred);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(gred->rta_len));
    rec_dbg(lev, "    [ tc_gred_sopt(%d) ]", sizeof(*sopt));
    rec_dbg(lev, "        DPs(%hu): %u", sizeof(sopt->DPs), sopt->DPs);
    rec_dbg(lev, "        def_DP(%hu): %u", sizeof(sopt->def_DP), sopt->def_DP);
    rec_dbg(lev, "        grio(%hu): %d", sizeof(sopt->grio), sopt->grio);
    rec_dbg(lev, "        flags(%hu): %d", sizeof(sopt->flags), sopt->flags);
    rec_dbg(lev, "        pad1(%hu): %d", sizeof(sopt->pad1), sopt->pad1);
}

#if HAVE_DECL_TCA_GRED_MAX_P
/*
 * debug attribute TCA_GRED_MAX_P
 */
void debug_tca_gred_max_p(int lev, struct rtattr *gred, const char *name)
{
    unsigned *max_p = (unsigned *)RTA_DATA(gred);
    int i;

    if(debug_rta_len_chk(lev, gred, name, sizeof(__u32) * MAX_DPs))
        return;

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(gred->rta_len));

    for(i = 0; i < MAX_DPs; i++)
        rec_dbg(lev+1, "%d(%hu): %u", i, sizeof(max_p[i]), max_p[i]);

}
#endif
