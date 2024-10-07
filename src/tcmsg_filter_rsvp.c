/*
 * tcmsg_filter_rsvp.c - traffic control filter message parser
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

#if HAVE_DECL_TCA_RSVP_UNSPEC
/*
 * parse rsvp options
 */
int parse_tca_options_rsvp(char *msg, char **mp, struct tcmsg *tcm, struct rtattr *tca)
{
    struct rtattr *rsvp[__TCA_RSVP_MAX];
    char *mp_tmp = *mp;

    parse_nested_rtattr(rsvp, TCA_RSVP_MAX, tca);

    if(rsvp[TCA_RSVP_CLASSID])
        if(parse_tca_classid(msg, mp, rsvp[TCA_RSVP_CLASSID]))
            return(1);

    if(rsvp[TCA_RSVP_DST])
        if(parse_tca_rsvp_dst(msg, mp, tcm, rsvp[TCA_RSVP_DST]))
            return(1);

    if(rsvp[TCA_RSVP_SRC])
        if(parse_tca_rsvp_src(msg, mp, tcm, rsvp[TCA_RSVP_SRC]))
            return(1);

    if(rsvp[TCA_RSVP_PINFO])
        if(parse_tca_rsvp_pinfo(msg, mp, rsvp[TCA_RSVP_PINFO]))
            return(1);

    if(*mp != mp_tmp)
        rec_log("%s", msg);

    /* rollback pointer */
    *mp = mp_tmp;

    /* logging for each attribute below */
    if(rsvp[TCA_RSVP_POLICE])
        if(parse_tca_act_options_police(msg, *mp, rsvp[TCA_RSVP_POLICE]))
            return(1);

    if(rsvp[TCA_RSVP_ACT])
        if(parse_tca_acts(msg, *mp, rsvp[TCA_RSVP_ACT]))
            return(1);

    return(0);
}

/*
 * parse attribute TCA_RSVP_DST
 */
int parse_tca_rsvp_dst(char *msg, char **mp, struct tcmsg *tcm, struct rtattr *rsvp)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = inet_ntop_tc_addr(tcm, rsvp, addr, sizeof(addr));
    if(res) {
        rec_log("error: %s: %s", __func__,
            (res == 1) ? strerror(errno) : "payload too short");
        return(1);
    }
    *mp = add_log(msg, *mp, "destination=%s ", addr);

    return(0);
}

/*
 * parse attribute TCA_RSVP_SRC
 */
int parse_tca_rsvp_src(char *msg, char **mp, struct tcmsg *tcm, struct rtattr *rsvp)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = inet_ntop_tc_addr(tcm, rsvp, addr, sizeof(addr));
    if(res) {
        rec_log("error: %s: %s", __func__,
            (res == 1) ? strerror(errno) : "payload too short");
        return(1);
    }
    *mp = add_log(msg, *mp, "source=%s ", addr);

    return(0);
}

/*
 * parse attribute TCA_RSVP_PINFO
 */
int parse_tca_rsvp_pinfo(char *msg, char **mp, struct rtattr *rsvp)
{
    struct tc_rsvp_pinfo *pinfo;
    struct tc_rsvp_gpi *dpi, *spi;
    struct protoent *proto;

    if(RTA_PAYLOAD(rsvp) < sizeof(*pinfo)) {
        rec_log("error: %s: -- payload too short --", __func__);
        return(1);
    }
    pinfo = (struct tc_rsvp_pinfo *)RTA_DATA(rsvp);
    dpi = &(pinfo->dpi);
    spi = &(pinfo->spi);
    proto = getprotobynumber(pinfo->protocol);

    *mp = add_log(msg, *mp, "dpi(key/mask/offset)=0x%08x/0x%08x/%d ",
        htonl(dpi->key), htonl(dpi->mask), dpi->offset);
    *mp = add_log(msg, *mp, "spi(key/mask/offset)=0x%08x/0x%08x/%d ",
        htonl(spi->key), htonl(spi->mask), spi->offset);
    *mp = add_log(msg, *mp, "tunnel(protocol/id/hdr)=%d(%s)/%d/%d ",
        pinfo->protocol, proto ? proto->p_name : "unknown",
        pinfo->tunnelid, pinfo->tunnelhdr);

    return(0);
}

/*
 * debug rsvp options
 */
void debug_tca_options_rsvp(int lev, struct tcmsg *tcm, struct rtattr *tca, const char *name)
{
    struct rtattr *rsvp[__TCA_RSVP_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(rsvp, TCA_RSVP_MAX, tca);

    if(rsvp[TCA_RSVP_CLASSID])
        debug_tca_classid(lev+1, rsvp[TCA_RSVP_CLASSID],
            "TCA_RSVP_CLASSID");

    if(rsvp[TCA_RSVP_DST])
        debug_rta_tc_addr(lev+1, tcm, rsvp[TCA_RSVP_DST],
            "TCA_RSVP_DST");

    if(rsvp[TCA_RSVP_SRC])
        debug_rta_tc_addr(lev+1, tcm, rsvp[TCA_RSVP_SRC],
            "TCA_RSVP_SRC");

    if(rsvp[TCA_RSVP_PINFO])
        debug_tca_rsvp_pinfo(lev+1, rsvp[TCA_RSVP_PINFO],
            "TCA_RSVP_PINFO");

    if(rsvp[TCA_RSVP_POLICE])
        debug_tca_act_options_police(lev+1, rsvp[TCA_RSVP_POLICE],
            "TCA_RSVP_POLICE");

    if(rsvp[TCA_RSVP_ACT])
        debug_tca_acts(lev+1, rsvp[TCA_RSVP_ACT],
            "TCA_RSVP_ACT");
}

/*
 * debug attribute TCA_RSVP_PINFO
 */
void debug_tca_rsvp_pinfo(int lev, struct rtattr *rsvp, const char *name)
{
    struct tc_rsvp_pinfo *pinfo;
    struct tc_rsvp_gpi *dpi, *spi;

    if(debug_rta_len_chk(lev, rsvp, name, sizeof(*pinfo)))
        return;

    pinfo = (struct tc_rsvp_pinfo *)RTA_DATA(rsvp);
    dpi = &(pinfo->dpi);
    spi = &(pinfo->spi);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(rsvp->rta_len));
    rec_dbg(lev, "    [ tc_rsvp_pinfo(%d) ]", sizeof(*pinfo));
    rec_dbg(lev, "        [ tc_rsvp_gpi dpi(%d) ]", sizeof(*dpi));
    rec_dbg(lev, "            key(%d): 0x%08x", sizeof(dpi->key), dpi->key);
    rec_dbg(lev, "            mask(%d): 0x%08x", sizeof(dpi->mask), dpi->mask);
    rec_dbg(lev, "            offset(%d): %d", sizeof(dpi->offset), dpi->offset);
    rec_dbg(lev, "        [ tc_rsvp_gpi spi(%d) ]", sizeof(*spi));
    rec_dbg(lev, "            key(%d): 0x%08x", sizeof(spi->key), spi->key);
    rec_dbg(lev, "            mask(%d): 0x%08x", sizeof(spi->mask), spi->mask);
    rec_dbg(lev, "            offset(%d): %d", sizeof(spi->offset), spi->offset);
    rec_dbg(lev, "        protocol(%d): %d", sizeof(pinfo->protocol), pinfo->protocol);
    rec_dbg(lev, "        tunnelid(%d): %d", sizeof(pinfo->tunnelid), pinfo->tunnelid);
    rec_dbg(lev, "        tunnelhdr(%d): %d", sizeof(pinfo->tunnelhdr), pinfo->tunnelhdr);
    rec_dbg(lev, "        pad(%d): %d", sizeof(pinfo->pad), pinfo->pad);
}
#endif
