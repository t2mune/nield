/*
 * tcmsg_filter_cgroup.c - traffic control filter message parser
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

#if HAVE_DECL_TCA_CGROUP_UNSPEC
/*
 * parse cgroup options
 */
int parse_tca_options_cgroup(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *cgroup[__TCA_CGROUP_MAX];

    parse_nested_rtattr(cgroup, TCA_CGROUP_MAX, tca);

    /* logging for each attribute below */
    if(cgroup[TCA_CGROUP_EMATCHES])
        if(parse_tca_ematch(msg, *mp, cgroup[TCA_CGROUP_EMATCHES]))
            return(1);

    if(cgroup[TCA_CGROUP_POLICE])
        if(parse_tca_act_options_police(msg, *mp, cgroup[TCA_CGROUP_POLICE]))
            return(1);

    if(cgroup[TCA_CGROUP_ACT])
        if(parse_tca_acts(msg, *mp, cgroup[TCA_CGROUP_ACT]))
            return(1);

    return(0);
}

/*
 * debug cgroup options
 */
void debug_tca_options_cgroup(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *cgroup[__TCA_CGROUP_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));

    parse_nested_rtattr(cgroup, TCA_CGROUP_MAX, tca);

    if(cgroup[TCA_CGROUP_ACT])
        debug_tca_acts(lev+1, cgroup[TCA_CGROUP_ACT],
            "TCA_CGROUP_ACT");

    if(cgroup[TCA_CGROUP_POLICE])
        debug_tca_act_options_police(lev+1, cgroup[TCA_CGROUP_POLICE],
            "TCA_CGROUP_POLICE");

    if(cgroup[TCA_CGROUP_EMATCHES])
        debug_tca_ematch(lev+1, cgroup[TCA_CGROUP_EMATCHES],
            "TCA_CGROUP_EMATCHES");
}
#endif
