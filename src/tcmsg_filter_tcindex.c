/*
 * tcmsg_filter_tcindex.c - traffic control filter message parser
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
 * parse tcindex options
 */
int parse_tca_options_tcindex(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *tcindex[__TCA_TCINDEX_MAX];
    char *mp_tmp = *mp;

    parse_nested_rtattr(tcindex, TCA_TCINDEX_MAX, tca);

    if(tcindex[TCA_TCINDEX_CLASSID])
        if(parse_tca_classid(msg, mp, tcindex[TCA_TCINDEX_CLASSID]))
            return(1);

    if(tcindex[TCA_TCINDEX_HASH])
        if(parse_tca_tcindex_hash(msg, mp, tcindex[TCA_TCINDEX_HASH]))
            return(1);

    if(tcindex[TCA_TCINDEX_MASK])
        if(parse_tca_tcindex_mask(msg, mp, tcindex[TCA_TCINDEX_MASK]))
            return(1);

    if(tcindex[TCA_TCINDEX_SHIFT])
        if(parse_tca_tcindex_shift(msg, mp, tcindex[TCA_TCINDEX_SHIFT]))
            return(1);

    if(tcindex[TCA_TCINDEX_FALL_THROUGH])
        if(parse_tca_tcindex_fall_through(msg, mp, tcindex[TCA_TCINDEX_FALL_THROUGH]))
            return(1);

    if(*mp != mp_tmp)
        rec_log("%s", msg);

    /* rollback pointer */
    *mp = mp_tmp;

    /* logging for each attribute below */
    if(tcindex[TCA_TCINDEX_POLICE])
        if(parse_tca_act_options_police(msg, *mp, tcindex[TCA_TCINDEX_POLICE]))
            return(1);

    if(tcindex[TCA_TCINDEX_ACT])
        if(parse_tca_acts(msg, *mp, tcindex[TCA_TCINDEX_ACT]))
            return(1);

    return(0);
}

/*
 * parse attribute TCA_TCINDEX_HASH
 */
int parse_tca_tcindex_hash(char *msg, char **mp, struct rtattr *tcindex)
{
    if(RTA_PAYLOAD(tcindex) < sizeof(unsigned short)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "hash=%hu ", *(unsigned short *)RTA_DATA(tcindex));

    return(0);
}

/*
 * parse attribute TCA_TCINDEX_MASK
 */
int parse_tca_tcindex_mask(char *msg, char **mp, struct rtattr *tcindex)
{
    if(RTA_PAYLOAD(tcindex) < sizeof(unsigned short)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "mask=0x%04x ", *(unsigned short *)RTA_DATA(tcindex));

    return(0);
}

/*
 * parse attribute TCA_TCINDEX_SHIFT
 */
int parse_tca_tcindex_shift(char *msg, char **mp, struct rtattr *tcindex)
{
    if(RTA_PAYLOAD(tcindex) < sizeof(int)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "shift=%d ", *(int *)RTA_DATA(tcindex));

    return(0);
}

/*
 * parse attribute TCA_TCINDEX_FALL_THROUGH
 */
int parse_tca_tcindex_fall_through(char *msg, char **mp, struct rtattr *tcindex)
{
    if(RTA_PAYLOAD(tcindex) < sizeof(int)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "flag=%s ",
        *(int *)RTA_DATA(tcindex) ? "fall_through" : "pass_on");

    return(0);
}

/*
 * debug tcindex options
 */
void debug_tca_options_tcindex(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *tcindex[__TCA_TCINDEX_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(tcindex, TCA_TCINDEX_MAX, tca);

    if(tcindex[TCA_TCINDEX_HASH])
        debug_rta_u16(lev+1, tcindex[TCA_TCINDEX_HASH],
            "TCA_TCINDEX_HASH", NULL);

    if(tcindex[TCA_TCINDEX_MASK])
        debug_rta_u16x(lev+1, tcindex[TCA_TCINDEX_MASK],
            "TCA_TCINDEX_MASK", NULL);

    if(tcindex[TCA_TCINDEX_SHIFT])
        debug_rta_s32(lev+1, tcindex[TCA_TCINDEX_SHIFT],
            "TCA_TCINDEX_SHIFT", NULL);

    if(tcindex[TCA_TCINDEX_FALL_THROUGH])
        debug_rta_s32x(lev+1, tcindex[TCA_TCINDEX_FALL_THROUGH],
            "TCA_TCINDEX_FALL_THROUGH", NULL);

    if(tcindex[TCA_TCINDEX_CLASSID])
        debug_tca_classid(lev+1, tcindex[TCA_TCINDEX_CLASSID],
            "TCA_TCINDEX_CLASSID");

    if(tcindex[TCA_TCINDEX_POLICE])
        debug_tca_act_options_police(lev+1, tcindex[TCA_TCINDEX_POLICE],
            "TCA_TCINDEX_POLICE");

    if(tcindex[TCA_TCINDEX_ACT])
        debug_tca_acts(lev+1, tcindex[TCA_TCINDEX_ACT],
            "TCA_TCINDEX_ACT");
}
