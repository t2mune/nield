/*
 * tcmsg_qdisc_choke.c - traffic control qdisc message parser
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

#if HAVE_DECL_TCA_CHOKE_UNSPEC
/*
 * parse choke options
 */
int parse_tca_options_choke(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *choke[__TCA_CHOKE_MAX];

    parse_nested_rtattr(choke, TCA_CHOKE_MAX, tca);

    if(choke[TCA_CHOKE_PARMS]) {
        struct tc_choke_qopt *qopt;
        char list[MAX_STR_SIZE] = "";

        if(RTA_PAYLOAD(choke[TCA_CHOKE_PARMS]) < sizeof(*qopt)) {
            rec_log("error: %s: TCA_CHOKE_PARMS: payload too short", __func__);
            return(1);
        }
        qopt = (struct tc_choke_qopt *)RTA_DATA(choke[TCA_CHOKE_PARMS]);

        *mp = add_log(msg, *mp, "limit=%u(packet) min=%u(packet) max=%u(packet) ",
            qopt->limit, qopt->qth_min, qopt->qth_max);
        if(qopt->flags) {
            conv_tc_red_flags(qopt->flags, list, sizeof(list), 0);
            *mp = add_log(msg, *mp, "flag=%s ", list);
        }
    }

#if HAVE_DECL_TCA_CHOKE_MAX_P
    if(choke[TCA_CHOKE_MAX_P]) {
        if(RTA_PAYLOAD(choke[TCA_CHOKE_MAX_P]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_CHOKE_MAX_P: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "probability=%g(%%) ",
            *(unsigned *)RTA_DATA(choke[TCA_CHOKE_MAX_P]) / pow(2, 32) * 100);
    }
#endif

    return(0);
}

/*
 * debug choke options
 */
void debug_tca_options_choke(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *choke[__TCA_CHOKE_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(choke, TCA_CHOKE_MAX, tca);

    if(choke[TCA_CHOKE_PARMS])
        debug_tca_choke_parms(lev+1, choke[TCA_CHOKE_PARMS],
            "TCA_CHOKE_PARMS");

    if(choke[TCA_CHOKE_STAB])
        debug_rta_ignore(lev+1, choke[TCA_CHOKE_STAB],
            "TCA_CHOKE_STAB");

#if HAVE_DECL_TCA_GRED_MAX_P
    if(choke[TCA_CHOKE_MAX_P])
        debug_rta_u32(lev+1, choke[TCA_CHOKE_MAX_P],
            "TCA_CHOKE_MAX_P", NULL);
#endif
}

/*
 * debug attribute TCA_CHOKE_PARMS
 */
void debug_tca_choke_parms(int lev, struct rtattr *choke, const char *name)
{
    struct tc_choke_qopt *qopt;
    char list[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, choke, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_choke_qopt *)RTA_DATA(choke);
    conv_tc_red_flags(qopt->flags, list, sizeof(list), 1);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(choke->rta_len));
    rec_dbg(lev, "    [ tc_choke_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        limit(%d): %d", sizeof(qopt->limit), qopt->limit);
    rec_dbg(lev, "        qth_min(%d): %u", sizeof(qopt->qth_min), qopt->qth_min);
    rec_dbg(lev, "        qth_max(%d): %u", sizeof(qopt->qth_max), qopt->qth_max);
    rec_dbg(lev, "        Wlog(%d): %d", sizeof(qopt->Wlog), qopt->Wlog);
    rec_dbg(lev, "        Plog(%d): %d", sizeof(qopt->Plog), qopt->Plog);
    rec_dbg(lev, "        Scell_log(%d): %d", sizeof(qopt->Scell_log), qopt->Scell_log);
    rec_dbg(lev, "        flags(%d): %d(%s)", sizeof(qopt->flags), qopt->flags, list);
}

/*
 * debug tc_choke_xstats
 */
void debug_tc_choke_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_choke_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_choke_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_choke_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        early(%d): %u", sizeof(xstats->early), xstats->early);
    rec_dbg(lev, "        pdrop(%d): %u", sizeof(xstats->pdrop), xstats->pdrop);
    rec_dbg(lev, "        other(%d): %u", sizeof(xstats->other), xstats->other);
    rec_dbg(lev, "        marked(%d): %u", sizeof(xstats->marked), xstats->marked);
    rec_dbg(lev, "        matched(%d): %u", sizeof(xstats->matched), xstats->matched);
}
#endif
