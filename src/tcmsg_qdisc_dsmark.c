/*
 * tcmsg_qdisc_dsmark.c - traffic control qdisc message parser
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

#if HAVE_DECL_TCA_DSMARK_UNSPEC
/*
 * parse dsmark options
 */
int parse_tca_options_dsmark(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *dsmark[__TCA_DSMARK_MAX];

    parse_nested_rtattr(dsmark, TCA_DSMARK_MAX, tca);

    if(dsmark[TCA_DSMARK_INDICES]) {
        if(RTA_PAYLOAD(dsmark[TCA_DSMARK_INDICES]) < sizeof(unsigned short)) {
            rec_log("error: %s: TCA_DSMARK_INDICES: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "indices=0x%04x ",
            *(unsigned short *)RTA_DATA(dsmark[TCA_DSMARK_INDICES]));
    }

    if(dsmark[TCA_DSMARK_DEFAULT_INDEX]) {
        if(RTA_PAYLOAD(dsmark[TCA_DSMARK_DEFAULT_INDEX]) < sizeof(unsigned short)) {
            rec_log("error: %s: TCA_DSMARK_DEFAULT_INDEX: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "default_index=0x%04x ",
            *(unsigned short *)RTA_DATA(dsmark[TCA_DSMARK_DEFAULT_INDEX]));
    }

    if(dsmark[TCA_DSMARK_SET_TC_INDEX])
        *mp = add_log(msg, *mp, "set_tc_index=on ");

    if(dsmark[TCA_DSMARK_VALUE]) {
        if(RTA_PAYLOAD(dsmark[TCA_DSMARK_VALUE]) < sizeof(unsigned char)) {
            rec_log("error: %s: TCA_DSMARK_VALUE: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "value=0x%02x ",
            *(unsigned char *)RTA_DATA(dsmark[TCA_DSMARK_VALUE]));
    }

    if(dsmark[TCA_DSMARK_MASK]) {
        if(RTA_PAYLOAD(dsmark[TCA_DSMARK_MASK]) < sizeof(unsigned char)) {
            rec_log("error: %s: TCA_DSMARK_MASK: payload too short", __func__);
            return(1);
        }
        *mp = add_log(msg, *mp, "mask=0x%02x ",
            *(unsigned char *)RTA_DATA(dsmark[TCA_DSMARK_MASK]));
    }

    return(0);
}

/*
 * debug dsmark options
 */
void debug_tca_options_dsmark(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *dsmark[__TCA_DSMARK_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(dsmark, TCA_DSMARK_MAX, tca);

    if(dsmark[TCA_DSMARK_INDICES])
        debug_rta_u16x(lev+1, dsmark[TCA_DSMARK_INDICES],
            "TCA_DSMARK_INDICES", NULL);

    if(dsmark[TCA_DSMARK_DEFAULT_INDEX])
        debug_rta_u16x(lev+1, dsmark[TCA_DSMARK_DEFAULT_INDEX],
            "TCA_DSMARK_DEFAULT_INDEX", NULL);

    if(dsmark[TCA_DSMARK_SET_TC_INDEX])
        debug_rta_none(lev+1, dsmark[TCA_DSMARK_SET_TC_INDEX],
            "TCA_DSMARK_SET_TC_INDEX");

    if(dsmark[TCA_DSMARK_MASK])
        debug_rta_u8x(lev+1, dsmark[TCA_DSMARK_MASK],
            "TCA_DSMARK_MASK", NULL);

    if(dsmark[TCA_DSMARK_VALUE])
        debug_rta_u8x(lev+1, dsmark[TCA_DSMARK_VALUE],
            "TCA_DSMARK_VALUE", NULL);
}
#endif
