/*
 * tcmsg_filter_flow.c - traffic control filter message parser
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

#if HAVE_DECL_TCA_FLOW_UNSPEC
/*
 * parse flow options
 */
int parse_tca_options_flow(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *flow[__TCA_FLOW_MAX];
    char *mp_tmp = *mp;

    parse_nested_rtattr(flow, TCA_FLOW_MAX, tca);

    if(flow[TCA_FLOW_BASECLASS])
        if(parse_tca_classid(msg, mp, flow[TCA_FLOW_BASECLASS]))
            return(1);

    if(flow[TCA_FLOW_KEYS])
        if(parse_tca_flow_keys(msg, mp, flow[TCA_FLOW_KEYS]))
            return(1);

    if(flow[TCA_FLOW_MODE])
        if(parse_tca_flow_mode(msg, mp, flow[TCA_FLOW_MODE]))
            return(1);

    if(flow[TCA_FLOW_MASK])
        if(parse_tca_mask(msg, mp, flow[TCA_FLOW_MASK]))
            return(1);

    if(flow[TCA_FLOW_XOR])
        if(parse_tca_flow_xor(msg, mp, flow[TCA_FLOW_XOR]))
            return(1);

    if(flow[TCA_FLOW_RSHIFT])
        if(parse_tca_flow_rshift(msg, mp, flow[TCA_FLOW_RSHIFT]))
            return(1);

    if(flow[TCA_FLOW_ADDEND])
        if(parse_tca_flow_addend(msg, mp, flow[TCA_FLOW_ADDEND]))
            return(1);

    if(flow[TCA_FLOW_DIVISOR])
        if(parse_tca_flow_divisor(msg, mp, flow[TCA_FLOW_DIVISOR]))
            return(1);

    if(flow[TCA_FLOW_PERTURB])
        if(parse_tca_flow_perturb(msg, mp, flow[TCA_FLOW_PERTURB]))
            return(1);

    if(*mp != mp_tmp)
        rec_log("%s", msg);

    /* rollback pointer */
    *mp = mp_tmp;

    /* logging for each attribute below */
    if(flow[TCA_FLOW_EMATCHES])
        if(parse_tca_ematch(msg, *mp, flow[TCA_FLOW_EMATCHES]))
            return(1);

    if(flow[TCA_FLOW_POLICE])
        if(parse_tca_act_options_police(msg, *mp, flow[TCA_FLOW_POLICE]))
            return(1);

    if(flow[TCA_FLOW_ACT])
        if(parse_tca_acts(msg, *mp, flow[TCA_FLOW_ACT]))
            return(1);

    return(0);
}

/*
 * parse attribute TCA_FLOW_KEYS
 */
int parse_tca_flow_keys(char *msg, char **mp, struct rtattr *flow)
{
    if(RTA_PAYLOAD(flow) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "keys=%s ", conv_flow_key(*(unsigned *)RTA_DATA(flow), 0));

    return(0);
}

/*
 * parse attribute TCA_FLOW_MODE
 */
int parse_tca_flow_mode(char *msg, char **mp, struct rtattr *flow)
{
    if(RTA_PAYLOAD(flow) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "mode=%s ",
        conv_flow_mode(*(unsigned *)RTA_DATA(flow), 0));

    return(0);
}

/*
 * parse attribute TCA_FLOW_XOR
 */
int parse_tca_flow_xor(char *msg, char **mp, struct rtattr *flow)
{
    if(RTA_PAYLOAD(flow) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "xor=0x%08x ", *(unsigned *)RTA_DATA(flow));

    return(0);
}

/*
 * parse attribute TCA_FLOW_RSHIFT
 */
int parse_tca_flow_rshift(char *msg, char **mp, struct rtattr *flow)
{
    if(RTA_PAYLOAD(flow) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "rshift=%u ", *(unsigned *)RTA_DATA(flow));

    return(0);
}

/*
 * parse attribute TCA_FLOW_ADDEND
 */
int parse_tca_flow_addend(char *msg, char **mp, struct rtattr *flow)
{
    if(RTA_PAYLOAD(flow) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "addend=0x%x ", *(unsigned *)RTA_DATA(flow));

    return(0);
}

/*
 * parse attribute TCA_FLOW_DIVISOR
 */
int parse_tca_flow_divisor(char *msg, char **mp, struct rtattr *flow)
{
    if(RTA_PAYLOAD(flow) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "divisor=%u ", *(unsigned *)RTA_DATA(flow));

    return(0);
}

/*
 * parse attribute TCA_FLOW_PERTURB
 */
int parse_tca_flow_perturb(char *msg, char **mp, struct rtattr *flow)
{
    if(RTA_PAYLOAD(flow) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "perturb=%u(sec) ", *(unsigned *)RTA_DATA(flow));

    return(0);
}

/*
 * debug flow options
 */
void debug_tca_options_flow(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *flow[__TCA_FLOW_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(flow, TCA_FLOW_MAX, tca);

    if(flow[TCA_FLOW_KEYS])
        debug_rta_u32(lev+1, flow[TCA_FLOW_KEYS],
            "TCA_FLOW_KEYS", conv_flow_key);

    if(flow[TCA_FLOW_MODE])
        debug_rta_u32(lev+1, flow[TCA_FLOW_MODE],
            "TCA_FLOW_MODE", conv_flow_mode);

    if(flow[TCA_FLOW_BASECLASS])
        debug_tca_classid(lev+1, flow[TCA_FLOW_BASECLASS],
            "TCA_FLOW_BASECLASS");

    if(flow[TCA_FLOW_RSHIFT])
        debug_rta_u32(lev+1, flow[TCA_FLOW_RSHIFT],
            "TCA_FLOW_RSHIT", NULL);

    if(flow[TCA_FLOW_ADDEND])
        debug_rta_u32x(lev+1, flow[TCA_FLOW_ADDEND],
            "TCA_FLOW_ADDEND", NULL);

    if(flow[TCA_FLOW_MASK])
        debug_rta_u32x(lev+1, flow[TCA_FLOW_MASK],
            "TCA_FLOW_MASK", NULL);

    if(flow[TCA_FLOW_XOR])
        debug_rta_u32x(lev+1, flow[TCA_FLOW_XOR],
            "TCA_FLOW_XOR", NULL);

    if(flow[TCA_FLOW_DIVISOR])
        debug_rta_u32(lev+1, flow[TCA_FLOW_DIVISOR],
            "TCA_FLOW_DIVISOR", NULL);

    if(flow[TCA_FLOW_ACT])
        debug_tca_acts(lev+1, flow[TCA_FLOW_ACT],
            "TCA_FLOW_ACT");

    if(flow[TCA_FLOW_POLICE])
        debug_tca_act_options_police(lev+1, flow[TCA_FLOW_POLICE],
            "TCA_FLOW_POLICE");

    if(flow[TCA_FLOW_EMATCHES])
        debug_tca_ematch(lev+1, flow[TCA_FLOW_EMATCHES],
            "TCA_FLOW_EMATCHES");

    if(flow[TCA_FLOW_PERTURB])
        debug_rta_u32(lev+1, flow[TCA_FLOW_PERTURB],
            "TCA_FLOW_PERTURB", NULL);
}

/*
 *  convert FLOW_KEY_* flags from number to string
 */
const char *conv_flow_key(unsigned flags, unsigned char debug)
{
    static char list[MAX_STR_SIZE];
    unsigned len = sizeof(list);

    strncpy(list, "", sizeof(list));
    if(!flags) {
        strncpy(list, debug ? "NONE" : "none", len);
        return((const char *)list);
    }
#define _FLOW_KEY(s1, s2) \
    if((flags & (1 << FLOW_KEY_##s1)) && (len - strlen(list) - 1 > 0)) \
        (flags &= ~(1 << FLOW_KEY_##s1)) ? \
            strncat(list, debug ? #s1 "," : #s2 ",", \
                len - strlen(list) - 1) : \
            strncat(list, debug ? #s1 : #s2, \
                len - strlen(list) - 1);
        _FLOW_KEY(SRC, src)
        _FLOW_KEY(DST, dst)
        _FLOW_KEY(PROTO, proto)
        _FLOW_KEY(PROTO_SRC, proto-src)
        _FLOW_KEY(PROTO_DST, proto-dst)
        _FLOW_KEY(IIF, iif)
        _FLOW_KEY(PRIORITY, priority)
        _FLOW_KEY(MARK, mark)
        _FLOW_KEY(NFCT, nfct)
        _FLOW_KEY(NFCT_SRC, nfct-src)
        _FLOW_KEY(NFCT_DST, nfct-dst)
        _FLOW_KEY(NFCT_PROTO_SRC, nfct-proto-src)
        _FLOW_KEY(NFCT_PROTO_DST, nfct-proto-dst)
        _FLOW_KEY(RTCLASSID, rt-classid)
        _FLOW_KEY(SKUID, sk-uid)
        _FLOW_KEY(SKGID, sk-gid)
        _FLOW_KEY(VLAN_TAG, vlan-tag)
#if HAVE_DECL_FLOW_KEY_RXHASH
        _FLOW_KEY(RXHASH, rxhash)
#endif
#undef _FLOW_KEY
    if(!strlen(list))
        strncpy(list, debug ? "UNKNOWN" : "unknown", len);

    return((const char *)list);
}

/*
 * convert FLOW_MODE_* protocol from number to string
 */
const char *conv_flow_mode(unsigned mode, unsigned char debug)
{
#define _FLOW_MODE(s1, s2) \
    if(mode == FLOW_MODE_##s1) \
        return(debug ? #s1 : #s2);
    _FLOW_MODE(MAP, map)
    _FLOW_MODE(HASH, hash)
#undef _FLOW_MODE
    return(debug ? "UNKNOWN" : "unknown");
}
#endif

