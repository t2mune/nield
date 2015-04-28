/*
 * tcmsg_qdisc_hfsc.c - traffic control qdisc message parser
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
 * parse hfsc options
 *
 * rt : realtime service curve
 * ls : linkshare service curve
 * sc : rt+ls service curve
 * ul : upperlimit service curve
 *
 */
int parse_tca_options_hfsc(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *hfsc[__TCA_HFSC_MAX];
    struct tc_hfsc_qopt *qopt;
    struct tc_service_curve *rsc = NULL, *fsc = NULL, *usc = NULL;

    if(RTA_PAYLOAD(tca) == sizeof(*qopt)) {
        qopt = (struct tc_hfsc_qopt *)RTA_DATA(tca);
        *mp = add_log(msg, *mp, "default-class=0x%x ", qopt->defcls);

        return(0);
    }

    parse_nested_rtattr(hfsc, TCA_HFSC_MAX, tca);

    if(hfsc[TCA_HFSC_RSC]) {
        if(RTA_PAYLOAD(hfsc[TCA_HFSC_RSC]) < sizeof(*rsc)) {
            rec_log("error: %s: TCA_HFSC_RSC: payload too short", __func__);
            return(1);
        }
        rsc = (struct tc_service_curve *)RTA_DATA(hfsc[TCA_HFSC_RSC]);
    }

    if(hfsc[TCA_HFSC_FSC]) {
        if(RTA_PAYLOAD(hfsc[TCA_HFSC_FSC]) < sizeof(*fsc)) {
            rec_log("error: %s: TCA_HFSC_FSC: payload too short", __func__);
            return(1);
        }
        fsc = (struct tc_service_curve *)RTA_DATA(hfsc[TCA_HFSC_FSC]);
    }

    if(hfsc[TCA_HFSC_USC]) {
        if(RTA_PAYLOAD(hfsc[TCA_HFSC_USC]) < sizeof(*usc)) {
            rec_log("error: %s: TCA_HFSC_USC: payload too short", __func__);
            return(1);
        }
        usc = (struct tc_service_curve *)RTA_DATA(hfsc[TCA_HFSC_USC]);
    }

    if(rsc && fsc && memcmp(rsc, fsc, sizeof(*rsc)) == 0)
        print_hfsc_sc(msg, mp, "realtime+linkshare", rsc);
    else {
        if(rsc)
            print_hfsc_sc(msg, mp, "realtime", rsc);
        if(fsc)
            print_hfsc_sc(msg, mp, "linkshare", fsc);
    }

    if(usc)
        print_hfsc_sc(msg, mp, "upperlimit", usc);

    return(0);
}

/*
 * parse hfsc survice curve
 */
int print_hfsc_sc(char *msg, char **mp, char *name, struct tc_service_curve *sc)
{
    char m1[MAX_STR_SIZE], m2[MAX_STR_SIZE], d[MAX_STR_SIZE];

    conv_unit_rate(m1, sizeof(m1), sc->m1);
    conv_unit_rate(m2, sizeof(m2), sc->m2);
    conv_unit_usec(d, sizeof(d), sc->d);

    *mp = add_log(msg, *mp, "%s(m1/d/m2)=%s/%s/%s ", name, m1, d, m2);

    return(0);
}

/*
 * debug hfsc options
 */
void debug_tca_options_hfsc(int lev, struct rtattr *tca, const char *name)
{
    struct tc_hfsc_qopt *qopt;
    struct rtattr *hfsc[__TCA_HFSC_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));

    if(RTA_PAYLOAD(tca) == sizeof(*qopt)) {
        qopt = (struct tc_hfsc_qopt *)RTA_DATA(tca);
        rec_dbg(lev, "    [ tc_hfsc_qopt(%d) ]", sizeof(*qopt));
        rec_dbg(lev, "        defcls(%d): 0x%x", sizeof(qopt->defcls), qopt->defcls);

        return;
    }

    parse_nested_rtattr(hfsc, TCA_HFSC_MAX, tca);

    if(hfsc[TCA_HFSC_RSC])
        debug_tca_hfsc_sc(lev+1, hfsc[TCA_HFSC_RSC],
            "TCA_HFSC_RSC");

    if(hfsc[TCA_HFSC_FSC])
        debug_tca_hfsc_sc(lev+1, hfsc[TCA_HFSC_FSC],
            "TCA_HFSC_FSC");

    if(hfsc[TCA_HFSC_USC])
        debug_tca_hfsc_sc(lev+1, hfsc[TCA_HFSC_USC],
            "TCA_HFSC_USC");
}

/*
 * debug attribute TCA_HFSC_*SC
 */
void debug_tca_hfsc_sc(int lev, struct rtattr *hfsc, const char *name)
{
    struct tc_service_curve *sc;

    if(debug_rta_len_chk(lev, hfsc, name, sizeof(*sc)))
        return;

    sc = (struct tc_service_curve *)RTA_DATA(hfsc);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(hfsc->rta_len));
    rec_dbg(lev, "    [ tc_service_curve(%d) ]", sizeof(*sc));
    rec_dbg(lev, "        m1(%d): %u", sizeof(sc->m1), sc->m1);
    rec_dbg(lev, "        d(%d): %u", sizeof(sc->d), sc->d);
    rec_dbg(lev, "        m2(%d): %u", sizeof(sc->m2), sc->m2);
}
