/*
 * tcmsg_qdisc_prio.c - traffic control qdisc message parser
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

/*
 * parse prio options
 */
int parse_tca_options_prio(char *msg, char **mp, struct rtattr *tca)
{
    struct tc_prio_qopt *qopt;
    int i;

    if(RTA_PAYLOAD(tca) < sizeof(*qopt)) {
        rec_log("error: %s: TCA_OPTIONS: payload too short", __func__);
        return(1);
    }
    qopt = (struct tc_prio_qopt *)RTA_DATA(tca);
    *mp = add_log(msg, *mp, "bands=%d priomap=", qopt->bands);

    for(i = 0; i < TC_PRIO_MAX + 1; i++)
        if(i == TC_PRIO_MAX)
            *mp = add_log(msg, *mp, "%d ", qopt->priomap[i]);
        else
            *mp = add_log(msg, *mp, "%d-", qopt->priomap[i]);

    return(0);
}

/*
 * debug prio options
 */
void debug_tca_options_prio(int lev, struct rtattr *tca, const char *name)
{
    struct tc_prio_qopt *qopt;
    char prio[MAX_STR_SIZE] = "";
    char *p = prio;
    int i, len = sizeof(prio);

    if(debug_rta_len_chk(lev, tca, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_prio_qopt *)RTA_DATA(tca);

    for(i = 0; i < TC_PRIO_MAX + 1; i++) {
        if(i == TC_PRIO_MAX)
            p += snprintf(p, len - strlen(prio), "%d ", qopt->priomap[i]);
        else
            p += snprintf(p, len - strlen(prio), "%d-", qopt->priomap[i]);
        if(len < p - prio) {
            rec_dbg(lev, "%s(%hu): -- priomap too long --",
                name, RTA_ALIGN(tca->rta_len));
            return;
        }
    }

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_prio_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        bands(%d): %d", sizeof(qopt->bands), qopt->bands);
    rec_dbg(lev, "        priomap(%d): %s", sizeof(qopt->priomap), prio);
}
