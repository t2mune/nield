/*
 * tcmsg_qdisc_red.c - traffic control qdisc message parser
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
 * parse red options
 */
int parse_tca_options_red(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *red[__TCA_RED_MAX];

    parse_nested_rtattr(red, TCA_RED_MAX, tca);

    if(red[TCA_RED_PARMS]) {
        struct tc_red_qopt *qopt;
        char limit[MAX_STR_SIZE] = "";
        char min[MAX_STR_SIZE] = "";
        char max[MAX_STR_SIZE] = "";
        char list[MAX_STR_SIZE] = "";

        if(RTA_PAYLOAD(red[TCA_RED_PARMS]) < sizeof(*qopt)) {
            rec_log("error: %s: TCA_RED_PARMS: payload too short", __func__);
            return(1);
        }
        qopt = (struct tc_red_qopt *)RTA_DATA(red[TCA_RED_PARMS]);

        conv_unit_size(limit, sizeof(limit), qopt->limit);
        conv_unit_size(min, sizeof(min), qopt->qth_min);
        conv_unit_size(max, sizeof(max), qopt->qth_max);

        *mp = add_log(msg, *mp, "limit=%s min=%s max=%s ", limit, min, max);
        if(qopt->flags) {
            conv_tc_red_flags(qopt->flags, list, sizeof(list), 0);
            *mp = add_log(msg, *mp, "flag=%s ", list);
        }
    }

#if HAVE_DECL_TCA_RED_MAX_P
    if(red[TCA_RED_MAX_P]) {
        if(RTA_PAYLOAD(red[TCA_RED_MAX_P]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_RED_MAX_P: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "probability=%g(%%) ",
            *(unsigned *)RTA_DATA(red[TCA_RED_MAX_P]) / pow(2, 32) * 100);
    }
#endif

    return(0);
}

/*
 * debug red options
 */
void debug_tca_options_red(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *red[__TCA_RED_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(red, TCA_RED_MAX, tca);

    if(red[TCA_RED_PARMS])
        debug_tca_red_parms(lev+1, red[TCA_RED_PARMS],
            "TCA_RED_PARMS");

    if(red[TCA_RED_STAB])
        debug_rta_ignore(lev+1, red[TCA_RED_STAB],
            "TCA_RED_STAB");

#if HAVE_DECL_TCA_RED_MAX_P
    if(red[TCA_RED_MAX_P])
        debug_rta_u32(lev+1, red[TCA_RED_MAX_P],
            "TCA_RED_MAX_P", NULL);
#endif
}

/*
 * debug attribute TCA_RED_PARMS
 */
void debug_tca_red_parms(int lev, struct rtattr *red, const char *name)
{
    struct tc_red_qopt *qopt;
    char list[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, red, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_red_qopt *)RTA_DATA(red);

    conv_tc_red_flags(qopt->flags, list, sizeof(list), 1);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(red->rta_len));
    rec_dbg(lev, "    [ tc_red_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        limit(%d): %d", sizeof(qopt->limit), qopt->limit);
    rec_dbg(lev, "        qth_min(%d): %u", sizeof(qopt->qth_min), qopt->qth_min);
    rec_dbg(lev, "        qth_max(%d): %u", sizeof(qopt->qth_max), qopt->qth_max);
    rec_dbg(lev, "        Wlog(%d): %d", sizeof(qopt->Wlog), qopt->Wlog);
    rec_dbg(lev, "        Plog(%d): %d", sizeof(qopt->Plog), qopt->Plog);
    rec_dbg(lev, "        Scell_log(%d): %d", sizeof(qopt->Scell_log), qopt->Scell_log);
    rec_dbg(lev, "        flags(%d): %d(%s)", sizeof(qopt->flags), qopt->flags, list);
}

/*
 * debug tc_red_xstats
 */
void debug_tc_red_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_red_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_red_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_red_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        early(%d): %u", sizeof(xstats->early), xstats->early);
    rec_dbg(lev, "        pdrop(%d): %u", sizeof(xstats->pdrop), xstats->pdrop);
    rec_dbg(lev, "        other(%d): %u", sizeof(xstats->other), xstats->other);
    rec_dbg(lev, "        marked(%d): %u", sizeof(xstats->marked), xstats->marked);
}

/*
 * convert red flags from number to string
 */
void conv_tc_red_flags(int flags, char *flags_list, int len, unsigned char debug)
{
    if(!flags) {
        strncpy(flags_list, debug ? "NONE" : "none", len);
        return;
    }
#define _TC_RED_FLAGS(s1, s2) \
    if((flags & TC_RED_##s1) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~TC_RED_##s1) ? \
            strncat(flags_list, debug ? #s1 "," : #s2 ",", \
                len - strlen(flags_list) - 1) : \
            strncat(flags_list, debug ? #s1 : #s2, \
                len - strlen(flags_list) - 1);
    _TC_RED_FLAGS(ECN, ecn)
    _TC_RED_FLAGS(HARDDROP, harddrop)
#ifdef TC_RED_ADAPTATIVE
    _TC_RED_FLAGS(ADAPTATIVE, adaptative)
#endif
#undef _TC_RED_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, debug ? "UNKNOWN" : "unknown", len);
}
