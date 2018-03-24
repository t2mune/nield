/*
 * tcmsg_qdisc_codel.c - traffic control qdisc message parser
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

#if HAVE_DECL_TCA_CODEL_UNSPEC
/*
 * parse codel options
 */
int parse_tca_options_codel(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *codel[__TCA_CODEL_MAX];

    parse_nested_rtattr(codel, TCA_CODEL_MAX, tca);

    if(codel[TCA_CODEL_LIMIT]) {
        if(RTA_PAYLOAD(codel[TCA_CODEL_LIMIT]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_CODEL_LIMIT: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "limit=%u(packet) ",
            *(unsigned *)RTA_DATA(codel[TCA_CODEL_LIMIT]));
    }

    if(codel[TCA_CODEL_TARGET]) {
        char target[MAX_STR_SIZE];

        if(RTA_PAYLOAD(codel[TCA_CODEL_TARGET]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_CODEL_TARGET: payload too short", __func__);
            return(1);
        }
        conv_unit_usec(target, sizeof(target),
            (double)*(unsigned *)RTA_DATA(codel[TCA_CODEL_TARGET]));
        *mp = add_log(msg, *mp, "target=%s ", target);
    }

    if(codel[TCA_CODEL_INTERVAL]) {
        char interval[MAX_STR_SIZE];

        if(RTA_PAYLOAD(codel[TCA_CODEL_INTERVAL]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_CODEL_INTERVAL: payload too short", __func__);
            return(1);
        }
        conv_unit_usec(interval, sizeof(interval),
            (double)*(unsigned *)RTA_DATA(codel[TCA_CODEL_INTERVAL]));
        *mp = add_log(msg, *mp, "interval=%s ", interval);
    }

    if(codel[TCA_CODEL_ECN]) {
        if(RTA_PAYLOAD(codel[TCA_CODEL_ECN]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_CODEL_ECN: payload too short", __func__);
            return(1);
        }
        if(*(unsigned *)RTA_DATA(codel[TCA_CODEL_ECN]))
            *mp = add_log(msg, *mp, "ecn=on ");
    }

    return(0);
}

/*
 * debug codel options
 */
void debug_tca_options_codel(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *codel[__TCA_CODEL_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(codel, TCA_CODEL_MAX, tca);

    if(codel[TCA_CODEL_TARGET])
        debug_rta_u32(lev+1, codel[TCA_CODEL_TARGET],
            "TCA_CODEL_TARGET", NULL);

    if(codel[TCA_CODEL_LIMIT])
        debug_rta_u32(lev+1, codel[TCA_CODEL_LIMIT],
            "TCA_CODEL_LIMIT", NULL);

    if(codel[TCA_CODEL_INTERVAL])
        debug_rta_u32(lev+1, codel[TCA_CODEL_INTERVAL],
            "TCA_CODEL_INTERVAL", NULL);

    if(codel[TCA_CODEL_ECN])
        debug_rta_u32(lev+1, codel[TCA_CODEL_ECN],
            "TCA_CODEL_ECN", NULL);
}

/*
 * debug tc_codel_xstats
 */
void debug_tc_codel_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_codel_xstats *xstats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*xstats)))
        return;

    xstats = (struct tc_codel_xstats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_codel_xstats(%d) ]", sizeof(*xstats));
    rec_dbg(lev, "        maxpacket(%d): %u", sizeof(xstats->maxpacket), xstats->maxpacket);
    rec_dbg(lev, "        count(%d): %u", sizeof(xstats->count), xstats->count);
    rec_dbg(lev, "        lastcount(%d): %u", sizeof(xstats->lastcount), xstats->lastcount);
    rec_dbg(lev, "        ldelay(%d): %u", sizeof(xstats->ldelay), xstats->ldelay);
    rec_dbg(lev, "        drop_next(%d): %d", sizeof(xstats->drop_next), xstats->drop_next);
    rec_dbg(lev, "        drop_overlimit(%d): %u",
        sizeof(xstats->drop_overlimit), xstats->drop_overlimit);
    rec_dbg(lev, "        ecn_mark(%d): %u", sizeof(xstats->ecn_mark), xstats->ecn_mark);
    rec_dbg(lev, "        dropping(%d): %u", sizeof(xstats->dropping), xstats->dropping);
}
#endif
