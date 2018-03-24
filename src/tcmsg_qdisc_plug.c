/*
 * tcmsg_qdisc_plug.c - traffic control qdisc message parser
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

#ifdef HAVE_STRUCT_TC_PLUG_QOPT_ACTION
/*
 * parse plug options
 */
int parse_tca_options_plug(char *msg, char **mp, struct rtattr *tca)
{
    struct tc_plug_qopt *qopt;
    char action[MAX_STR_SIZE] = "";

    if(RTA_PAYLOAD(tca) < sizeof(*qopt)) {
        rec_log("error: %s: TCA_OPTIONS: payload too short", __func__);
        return(1);
    }
    qopt = (struct tc_plug_qopt *)RTA_DATA(tca);

    if(qopt->action == TCQ_PLUG_BUFFER)
        strncpy(action, "buffer", sizeof(action));
    else if(qopt->action == TCQ_PLUG_RELEASE_ONE)
        strncpy(action, "release_one", sizeof(action));
    else if(qopt->action == TCQ_PLUG_RELEASE_INDEFINITE)
        strncpy(action, "release_indefinite", sizeof(action));

    *mp = add_log(msg, *mp, "action=%s limit=%u ", action, qopt->limit);

    return(0);
}

/*
 * debug plug options
 */
void debug_tca_options_plug(int lev, struct rtattr *tca, const char *name)
{
    struct tc_plug_qopt *qopt;

    if(debug_rta_len_chk(lev, tca, name, sizeof(*qopt)))
        return;

    qopt = (struct tc_plug_qopt *)RTA_DATA(tca);
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    rec_dbg(lev, "    [ tc_plug_qopt(%d) ]", sizeof(*qopt));
    rec_dbg(lev, "        action(%d): %d(%s)",
        sizeof(qopt->action), qopt->action, conv_tcq_plug_action(qopt->action));
    rec_dbg(lev, "        limit(%d): %u", qopt->limit);
}

/*
 *  convert TCQ_PLUG flags from number to string
 */
const char *conv_tcq_plug_action(int action)
{
#define _TCQ_PLUG_ACTION(s) \
    if(action == TCQ_PLUG_##s) \
        return(#s);
    _TCQ_PLUG_ACTION(BUFFER);
    _TCQ_PLUG_ACTION(RELEASE_ONE);
    _TCQ_PLUG_ACTION(RELEASE_INDEFINITE);
#undef _TCQ_PLUG_ACTION
    return("UNKNOWN");
}
#endif
