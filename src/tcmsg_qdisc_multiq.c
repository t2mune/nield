/*
 * tcmsg_qdisc_multiq.c - traffic control qdisc message parser
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

#ifdef HAVE_STRUCT_TC_MULTIQ_QOPT_BANDS
/*
 * parse multiq options
 */
int parse_tca_options_multiq(char *msg, char **mp, struct rtattr *tca)
{
    struct tc_multiq_qopt *qopt;

    if(RTA_PAYLOAD(tca) < sizeof(*qopt)) {
        rec_log("error: %s: TCA_OPTIONS: payload too short", __func__);
        return(1);
    }
    qopt = (struct tc_multiq_qopt *)RTA_DATA(tca);

    *mp = add_log(msg, *mp, "bands=%d max=%d ", qopt->bands, qopt->max_bands);

    return(0);
}

/*
 * debug multiq options
 */
void debug_tca_options_multiq(int lev, struct rtattr *tca, const char *name)
{
    struct tc_multiq_qopt *qopt;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_multiq_qopt *)RTA_DATA(tca);
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_multiq_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        bands(%d): %d", sizeof(qopt->bands), qopt->bands);
    rec_dbg(lev, "        max_bands(%d): %d", sizeof(qopt->max_bands), qopt->max_bands);
}
#endif
