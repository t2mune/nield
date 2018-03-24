/*
 * tcmsg_qdisc_drr.c - traffic control qdisc message parser
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

#if HAVE_DECL_TCA_DRR_UNSPEC
/*
 * parse drr options
 */
int parse_tca_options_drr(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *drr[__TCA_NETEM_MAX];
    char quantum[MAX_STR_SIZE];

    parse_nested_rtattr(drr, TCA_DRR_MAX, tca);

    if(drr[TCA_DRR_QUANTUM]) {
        if(RTA_PAYLOAD(drr[TCA_DRR_QUANTUM]) < sizeof(unsigned)) {
            rec_log("error: %s: TCA_DRR_QUANTUM: payload too short", __func__);
            return(1);
        }
        conv_unit_size(quantum, sizeof(quantum),
            (double)*(unsigned *)RTA_DATA(drr[TCA_DRR_QUANTUM]));
        *mp = add_log(msg, *mp, "quantum=%s ", quantum);
    }

    return(0);
}

/*
 * debug drr options
 */
void debug_tca_options_drr(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *drr[__TCA_DRR_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));

    parse_nested_rtattr(drr, TCA_DRR_MAX, tca);

    if(drr[TCA_DRR_QUANTUM])
        debug_rta_u32(lev+1, drr[TCA_DRR_QUANTUM],
            "TCA_DRR_QUANTUM", NULL);
}

/*
 * debug tc_drr_xstats
 */
void debug_tc_drr_xstats(int lev, struct rtattr *tca, const char *name)
{
    struct tc_drr_stats *stats;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*stats)))
        return;

    stats = (struct tc_drr_stats *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_drr_stats(%d) ]", sizeof(*stats));
    rec_dbg(lev, "        deficit(%d): %u", sizeof(stats->deficit), stats->deficit);
}
#endif
