/*
 * tcmsg_filter_route.c - traffic control filter message parser
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
 * parse route options
 */
int parse_tca_options_route(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *route[__TCA_ROUTE4_MAX];
    char *mp_tmp = *mp;

    parse_nested_rtattr(route, TCA_ROUTE4_MAX, tca);

    if(route[TCA_ROUTE4_CLASSID])
        if(parse_tca_classid(msg, mp, route[TCA_ROUTE4_CLASSID]))
            return(1);

    if(route[TCA_ROUTE4_FROM])
        if(parse_tca_route4_from(msg, mp, route[TCA_ROUTE4_FROM]))
            return(1);

    if(route[TCA_ROUTE4_IIF])
        if(parse_tca_route4_iif(msg, mp, route[TCA_ROUTE4_IIF]))
            return(1);

    if(route[TCA_ROUTE4_TO])
        if(parse_tca_route4_to(msg, mp, route[TCA_ROUTE4_TO]))
            return(1);

    if(*mp != mp_tmp)
        rec_log("%s", msg);

    /* rollback pointer */
    *mp = mp_tmp;

    /* logging for each attribute below */
    if(route[TCA_ROUTE4_POLICE])
        if(parse_tca_act_options_police(msg, *mp, route[TCA_RSVP_POLICE]))
            return(1);

    if(route[TCA_ROUTE4_ACT])
        if(parse_tca_acts(msg, *mp, route[TCA_RSVP_ACT]))
            return(1);

    return(0);
}

/*
 * parse attribute TCA_ROUTE4_FROM
 */
int parse_tca_route4_from(char *msg, char **mp, struct rtattr *route)
{
    if(RTA_PAYLOAD(route) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "from(realm)=%u ", *(unsigned *)RTA_DATA(route));

    return(0);
}

/*
 * parse attribute TCA_ROUTE4_IIF
 */
int parse_tca_route4_iif(char *msg, char **mp, struct rtattr *route)
{
    int ifindex;
    char ifname[IFNAMSIZ];

    if(RTA_PAYLOAD(route) < sizeof(ifindex)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    ifindex = *(int *)RTA_DATA(route);
    if_indextoname_from_lists(ifindex, ifname);

    *mp = add_log(msg, *mp, "from(interface)=%s ", ifname);

    return(0);
}

/*
 * parse attribute TCA_ROUTE4_TO
 */
int parse_tca_route4_to(char *msg, char **mp, struct rtattr *route)
{
    if(RTA_PAYLOAD(route) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "to(realm)=%u ", *(unsigned *)RTA_DATA(route));

    return(0);
}

/*
 * debug route options
 */
void debug_tca_options_route(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *route[__TCA_ROUTE4_MAX];

    rec_dbg(lev, "%s(hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(route, TCA_ROUTE4_MAX, tca);

    if(route[TCA_ROUTE4_CLASSID])
        debug_tca_classid(lev+1, route[TCA_ROUTE4_CLASSID],
            "TCA_ROUTE4_CLASSID");

    if(route[TCA_ROUTE4_TO])
        debug_rta_u32(lev+1, route[TCA_ROUTE4_TO],
            "TCA_ROUTE4_TO", NULL);

    if(route[TCA_ROUTE4_FROM])
        debug_rta_u32(lev+1, route[TCA_ROUTE4_FROM],
            "TCA_ROUTE4_FROM", NULL);

    if(route[TCA_ROUTE4_IIF])
        debug_rta_ifindex(lev+1, route[TCA_ROUTE4_IIF],
            "TCA_ROUTE4_IIF");

    if(route[TCA_ROUTE4_POLICE])
        debug_tca_act_options_police(lev+1, route[TCA_ROUTE4_POLICE],
            "TCA_ROUTE4_POLICE");

    if(route[TCA_ROUTE4_ACT])
        debug_tca_acts(lev+1, route[TCA_ROUTE4_ACT],
            "TCA_ROUTE4_ACT");
}
