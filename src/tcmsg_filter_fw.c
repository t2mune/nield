/*
 * tcmsg_filter_fw.c - traffic control filter message parser
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

/*
 * parse fw options
 */
int parse_tca_options_fw(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *fw[__TCA_FW_MAX];
    char *mp_tmp = *mp;

    parse_nested_rtattr(fw, TCA_FW_MAX, tca);

    if(fw[TCA_FW_CLASSID])
        if(parse_tca_classid(msg, mp, fw[TCA_FW_CLASSID]))
            return(1);

    if(fw[TCA_FW_INDEV])
        if(parse_tca_indev(msg, mp, fw[TCA_FW_INDEV]))
            return(1);

#if HAVE_DECL_TCA_FW_MASK
    if(fw[TCA_FW_MASK])
        if(parse_tca_mask(msg, mp, fw[TCA_FW_MASK]))
            return(1);
#endif

    if(*mp != mp_tmp)
        rec_log("%s", msg);

    /* rollback pointer */
    *mp = mp_tmp;

    /* logging for each attribute below */
    if(fw[TCA_FW_POLICE])
        if(parse_tca_act_options_police(msg, *mp, fw[TCA_FW_POLICE]))
            return(1);

    if(fw[TCA_FW_ACT])
        if(parse_tca_acts(msg, *mp, fw[TCA_FW_ACT]))
            return(1);

    return(0);
}

/*
 * debug fw options
 */
void debug_tca_options_fw(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *fw[__TCA_FW_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(fw, TCA_FW_MAX, tca);

    if(fw[TCA_FW_CLASSID])
        debug_tca_classid(lev+1, fw[TCA_FW_CLASSID],
            "TCA_FW_CLASSID");

    if(fw[TCA_FW_POLICE])
        debug_tca_act_options_police(lev+1, fw[TCA_FW_POLICE],
            "TCA_FW_POLICE");

    if(fw[TCA_FW_INDEV])
        debug_rta_str(lev+1, fw[TCA_FW_INDEV],
            "TCA_FW_INDEV", NULL, IFNAMSIZ);

    if(fw[TCA_FW_ACT])
        debug_tca_acts(lev+1, fw[TCA_FW_ACT],
            "TCA_FW_ACT");

#if HAVE_DECL_TCA_FW_MASK
    if(fw[TCA_FW_MASK])
        debug_rta_u32x(lev+1, fw[TCA_FW_MASK],
            "TCA_FW_MASK", NULL);
#endif
}
