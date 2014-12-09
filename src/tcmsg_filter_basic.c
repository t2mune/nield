/*
 * tcmsg_filter_basic.c - traffic control filter message parser
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
 * parse basic options
 */
int parse_tca_options_basic(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *basic[__TCA_BASIC_MAX];
    char *mp_tmp = *mp;

    parse_nested_rtattr(basic, TCA_BASIC_MAX, tca);

    if(basic[TCA_BASIC_CLASSID])
        if(parse_tca_classid(msg, mp, basic[TCA_BASIC_CLASSID]))
            return(1);

    if(*mp != mp_tmp)
        rec_log("%s", msg);

    /* rollback pointer */
    *mp = mp_tmp;

    /* logging for each attribute below */
    if(basic[TCA_BASIC_EMATCHES])
        if(parse_tca_ematch(msg, *mp, basic[TCA_BASIC_EMATCHES]))
            return(1);

    if(basic[TCA_BASIC_POLICE])
        if(parse_tca_act_options_police(msg, *mp, basic[TCA_BASIC_POLICE]))
            return(1);

    if(basic[TCA_BASIC_ACT])
        if(parse_tca_acts(msg, *mp, basic[TCA_BASIC_ACT]))
            return(1);

    return(0);
}

/*
 * debug basic options
 */
void debug_tca_options_basic(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *basic[__TCA_BASIC_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(basic, TCA_BASIC_MAX, tca);

    if(basic[TCA_BASIC_CLASSID])
        debug_tca_classid(lev+1, basic[TCA_BASIC_CLASSID],
            "TCA_BASIC_CLASSID");

    if(basic[TCA_BASIC_EMATCHES])
        debug_tca_ematch(lev+1, basic[TCA_BASIC_EMATCHES],
            "TCA_BASIC_EMATCHES");

    if(basic[TCA_BASIC_ACT])
        debug_tca_acts(lev+1, basic[TCA_BASIC_ACT],
            "TCA_BASIC_ACT");

    if(basic[TCA_BASIC_POLICE])
        debug_tca_act_options_police(lev+1, basic[TCA_BASIC_POLICE],
            "TCA_BASIC_POLICE");
}
