/*
 * tcmsg_qdisc_fifo.c - traffic control qdisc message parser
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
 * parse pfifo options
 */
int parse_tca_options_pfifo(char *msg, char **mp, struct rtattr *tca)
{
    struct tc_fifo_qopt *qopt;

    if(RTA_PAYLOAD(tca) < sizeof(*qopt)) {
        rec_log("error: %s: TCA_OPTIONS: payload too short", __func__);
        return(1);
    }

    qopt = (struct tc_fifo_qopt *)RTA_DATA(tca);

    *mp = add_log(msg, *mp, "limit=%d(packet) ", qopt->limit);

    return(0);
}

/*
 * parse bfifo options
 */
int parse_tca_options_bfifo(char *msg, char **mp, struct rtattr *tca)
{
    struct tc_fifo_qopt *qopt;
    char limit[MAX_STR_SIZE];

    if(RTA_PAYLOAD(tca) < sizeof(*qopt)) {
        rec_log("error: %s: TCA_OPTIONS: payload too short", __func__);
        return(1);
    }

    qopt = (struct tc_fifo_qopt *)RTA_DATA(tca);

    conv_unit_size(limit, sizeof(limit), qopt->limit);
    *mp = add_log(msg, *mp, "limit=%s", limit);

    return(0);
}

/*
 * debug fifo options
 */
void debug_tca_options_fifo(int lev, struct rtattr *tca, const char *name)
{
    struct tc_fifo_qopt *qopt;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_fifo_qopt *)RTA_DATA(tca);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_fifo_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        limit(%d): %d", sizeof(qopt->limit), qopt->limit);
}
