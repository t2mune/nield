/*
 * tcmsg_filter_u32.c - traffic control filter message parser
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
 * parse u32 options
 */
int parse_tca_options_u32(char *msg, char **mp, struct rtattr *tca)
{
    struct rtattr *u32[__TCA_U32_MAX];
    char *mp_tmp = *mp;

    parse_nested_rtattr(u32, TCA_U32_MAX, tca);

    if(u32[TCA_U32_CLASSID])
        if(parse_tca_classid(msg, mp, u32[TCA_U32_CLASSID]))
            return(1);

    if(u32[TCA_U32_HASH])
        if(parse_tca_u32_hash(msg, mp, u32[TCA_U32_HASH]))
            return(1);

    if(u32[TCA_U32_LINK])
        if(parse_tca_u32_link(msg, mp, u32[TCA_U32_LINK]))
            return(1);

    if(u32[TCA_U32_DIVISOR])
        if(parse_tca_u32_divisor(msg, mp, u32[TCA_U32_DIVISOR]))
            return(1);

    if(u32[TCA_U32_INDEV])
        if(parse_tca_indev(msg, mp, u32[TCA_U32_INDEV]))
            return(1);

    if(u32[TCA_U32_MARK])
        if(parse_tca_u32_mark(msg, mp, u32[TCA_U32_MARK]))
            return(1);

    if(*mp != mp_tmp)
        rec_log("%s", msg);

    /* rollback pointer */
    *mp = mp_tmp;

    /* logging for each attribute below */
    if(u32[TCA_U32_SEL])
        if(parse_tca_u32_sel(msg, *mp, u32[TCA_U32_SEL]))
            return(1);

    if(u32[TCA_U32_POLICE])
        if(parse_tca_act_options_police(msg, *mp, u32[TCA_U32_POLICE]))
            return(1);

    if(u32[TCA_U32_ACT])
        if(parse_tca_acts(msg, *mp, u32[TCA_U32_ACT]))
            return(1);

    return(0);
}

/*
 * parse attribute TCA_U32_HASH
 */
int parse_tca_u32_hash(char *msg, char **mp, struct rtattr *u32)
{
    unsigned htid;

    if(RTA_PAYLOAD(u32) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    htid = *(unsigned *)RTA_DATA(u32);

    *mp = add_log(msg, *mp, "hash(table/bucket)=0x%x/0x%x ",
        TC_U32_USERHTID(htid), TC_U32_HASH(htid));

    return(0);
}

/*
 * parse attribute TCA_U32_LINK
 */
int parse_tca_u32_link(char *msg, char **mp, struct rtattr *u32)
{
    char handle[MAX_STR_SIZE] = "";

    if(RTA_PAYLOAD(u32) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    parse_u32_handle(handle, sizeof(handle), *(unsigned *)RTA_DATA(u32));
    *mp = add_log(msg, *mp, "link=%s ", handle);

    return(0);
}

/*
 * parse attribute TCA_U32_DIVISOR
 */
int parse_tca_u32_divisor(char *msg, char **mp, struct rtattr *u32)
{
    if(RTA_PAYLOAD(u32) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "divisor=%d ", *(unsigned *)RTA_DATA(u32));

    return(0);
}

/*
 * parse attribute TCA_U32_MARK
 */
int parse_tca_u32_mark(char *msg, char **mp, struct rtattr *u32)
{
    struct tc_u32_mark *mark;

    if(RTA_PAYLOAD(u32) < sizeof(*mark)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    mark = (struct tc_u32_mark *)RTA_DATA(u32);
    *mp = add_log(msg, *mp, "mark(value/mask)=0x%04x/0x%04x ", mark->val, mark->mask);

    return(0);
}

/*
 * parse attribute TCA_U32_SEL
 */
int parse_tca_u32_sel(char *msg, char *mp, struct rtattr *u32)
{
    struct tc_u32_sel *sel;
    char flags_list[MAX_STR_SIZE] = "";
    char *mp_tmp = mp;

    if(RTA_PAYLOAD(u32) < sizeof(*sel)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    sel = (struct tc_u32_sel *)RTA_DATA(u32);
    conv_tc_u32_flags(sel->flags, flags_list, sizeof(flags_list),  0),
    add_log(msg, mp, "flags=%s offshift=%d nkeys=%d offmask=0x%04x "
        "off=%hu offoff=%hd hoff=%hd hmask=0x%08x ",
        flags_list, sel->offshift, sel->nkeys, ntohs(sel->offmask),
        sel->off, sel->offoff, sel->hoff, ntohl(sel->hmask));
    rec_log("%s", msg);

    /* rollback pointer */
    mp = mp_tmp;

    int i, len;
    struct tc_u32_key *keys = sel->keys;

    len = sizeof(*sel) + (sizeof(*keys) * sel->nkeys);
    if(RTA_PAYLOAD(u32) < len) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }

    for(i = 0; i < sel->nkeys; i++, keys++) {
        add_log(msg, mp, "key=%d value=0x%08x mask=0x%08x offset=%d offmask=0x%08x ",
            i + 1, ntohl(keys->val), ntohl(keys->mask),
            keys->off, ntohl(keys->offmask));
        rec_log("%s", msg);
    }

    return(0);
}

/*
 * debug u32 options
 */
void debug_tca_options_u32(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *u32[__TCA_U32_MAX];

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));
    parse_nested_rtattr(u32, TCA_U32_MAX, tca);

    if(u32[TCA_U32_CLASSID])
        debug_tca_classid(lev+1, u32[TCA_U32_CLASSID],
            "TCA_U32_CLASSID");

    if(u32[TCA_U32_HASH])
        debug_rta_u32x(lev+1, u32[TCA_U32_HASH],
            "TCA_U32_HASH", conv_tca_u32_hash);

    if(u32[TCA_U32_LINK])
        debug_tca_u32_link(lev+1, u32[TCA_U32_LINK],
            "TCA_U32_LINK");

    if(u32[TCA_U32_DIVISOR])
        debug_rta_u32(lev+1, u32[TCA_U32_DIVISOR],
            "TCA_U32_DIVISOR", NULL);

    if(u32[TCA_U32_SEL])
        debug_tca_u32_sel(lev+1, u32[TCA_U32_SEL],
            "TCA_U32_SEL");

    if(u32[TCA_U32_POLICE])
        debug_tca_act_options_police(lev+1, u32[TCA_U32_POLICE],
            "TCA_U32_POLICE");

    if(u32[TCA_U32_ACT])
        debug_tca_acts(lev+1, u32[TCA_U32_ACT],
            "TCA_U32_ACT");

    if(u32[TCA_U32_INDEV])
        debug_rta_str(lev+1, u32[TCA_U32_INDEV],
            "TCA_U32_INDEV", NULL, IFNAMSIZ);

    if(u32[TCA_U32_PCNT])
        debug_tca_u32_pcnt(lev+1, u32,
            "TCA_U32_PCNT");

    if(u32[TCA_U32_MARK])
        debug_tca_u32_mark(lev+1, u32[TCA_U32_MARK],
            "TCA_U32_MARK");
}

/*
 * debug attribute TCA_U32_LINK
 */
void debug_tca_u32_link(int lev, struct rtattr *u32, const char *name)
{
    unsigned n_handle;
    char s_handle[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, u32, name, sizeof(n_handle)))
        return;

    n_handle = *(unsigned *)RTA_DATA(u32);
    parse_u32_handle(s_handle, sizeof(s_handle), n_handle);

    rec_dbg(lev, "%s(%hu): 0x%08x(%s)",
        name, RTA_ALIGN(u32->rta_len), n_handle, s_handle);
}

/*
 * debug attribute TCA_U32_SEL
 */
void debug_tca_u32_sel(int lev, struct rtattr *u32, const char *name)
{
    struct tc_u32_sel *sel;
    struct tc_u32_key *keys;
    char flags_list[MAX_STR_SIZE] = "";
    int i, len;

    if(debug_rta_len_chk(lev, u32, name, sizeof(*sel)))
        return;

    sel = (struct tc_u32_sel *)RTA_DATA(u32);
    conv_tc_u32_flags(sel->flags, flags_list, sizeof(flags_list), 1);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(u32->rta_len));
    rec_dbg(lev, "    [ tc_u32_sel(%d) ]", sizeof(*sel));
    rec_dbg(lev, "        flags(%d): %d(%s)", sizeof(sel->flags), sel->flags, flags_list);
    rec_dbg(lev, "        offshift(%d): %d", sizeof(sel->offshift), sel->offshift);
    rec_dbg(lev, "        nkeys(%d): %d", sizeof(sel->nkeys), sel->nkeys);
    rec_dbg(lev, "        offmask(%d): 0x%04x", sizeof(sel->offmask), sel->offmask);
    rec_dbg(lev, "        off(%d): %hu", sizeof(sel->off), sel->off);
    rec_dbg(lev, "        offoff(%d): %hd", sizeof(sel->offoff), sel->offoff);
    rec_dbg(lev, "        hoff(%d): %hd", sizeof(sel->hoff), sel->hoff);
    rec_dbg(lev, "        hmask(%d): 0x%08x", sizeof(sel->hmask), sel->hmask);

    len = sizeof(*sel) + (sizeof(*keys) * sel->nkeys);
    if(RTA_PAYLOAD(u32) < len) {
        rec_dbg(lev, "        keys[0](%d): -- payload too short --",
            RTA_PAYLOAD(u32) - sizeof(*sel));
        return;
    }

    keys = sel->keys;
    for(i = 0; i < sel->nkeys; i++, keys++) {
        rec_dbg(lev+2, "[ tc_u32_key keys[%d](%d) ]", i, sizeof(*keys));
        rec_dbg(lev+2, "    mask(%d): 0x%08x", sizeof(keys->mask), keys->mask); /* AND */
        rec_dbg(lev+2, "    val(%d): 0x%08x", sizeof(keys->val), keys->val); /* XOR */
        rec_dbg(lev+2, "    off(%d): %d", sizeof(keys->off), keys->off); /* Offset */
        rec_dbg(lev+2, "    offmask(%d): 0x%08x", sizeof(keys->offmask), keys->offmask);
    }
}

/*
 * debug attribute TCA_U32_PCNT
 */
void debug_tca_u32_pcnt(int lev, struct rtattr *u32[], const char *name)
{
    struct tc_u32_pcnt *pcnt;
    struct tc_u32_sel *sel;
    unsigned long *kcnts;
    int i, len;

    if(debug_rta_len_chk(lev, u32[TCA_U32_PCNT], name, sizeof(*pcnt)))
        return;

    pcnt = (struct tc_u32_pcnt *)RTA_DATA(u32[TCA_U32_PCNT]);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(u32[TCA_U32_PCNT]->rta_len));
    rec_dbg(lev, "    [ tc_u32_pcnt(%d) ]", sizeof(*pcnt));
    rec_dbg(lev, "        rcnt(%d): %lu", sizeof(pcnt->rcnt), pcnt->rcnt);
    rec_dbg(lev, "        rhit(%d): %lu", sizeof(pcnt->rhit), pcnt->rhit);

    if(RTA_PAYLOAD(u32[TCA_U32_SEL]) < sizeof(*sel))
        return;

    sel = RTA_DATA(u32[TCA_U32_SEL]);

    len = sizeof(*pcnt) + (sel->nkeys * sizeof(unsigned long));
    if(RTA_PAYLOAD(u32[TCA_U32_PCNT]) < len) {
        rec_dbg(lev, "        kcnts[0](%d): -- payload too short --",
            RTA_PAYLOAD(u32[TCA_U32_PCNT]) - sizeof(*pcnt));
        return;
    }

    kcnts = (unsigned long *)pcnt->kcnts;
    for(i = 0; i < sel->nkeys; i++, kcnts++)
        rec_dbg(lev, "        kcnts[%d](%d): %lu", i, sizeof(*kcnts), *kcnts);
}

/*
 * debug attribute TCA_U32_MARK
 */
void debug_tca_u32_mark(int lev, struct rtattr *u32, const char *name)
{
    struct tc_u32_mark *mark;

    if(debug_rta_len_chk(lev, u32, name, sizeof(*mark)))
        return;

    mark = (struct tc_u32_mark *)RTA_DATA(u32);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(u32->rta_len));
    rec_dbg(lev, "    [ tc_u32_mark(%d) ]", sizeof(*mark));
    rec_dbg(lev, "        val(%d): 0x%08x", sizeof(mark->val), mark->val);
    rec_dbg(lev, "        mask(%d): 0x%08x", sizeof(mark->mask), mark->mask);
    rec_dbg(lev, "        success(%d): 0x%08x", sizeof(mark->success), mark->success);
}

/*
 * convert TCA_U32_HASH from number to string
 */
const char *conv_tca_u32_hash(unsigned num, unsigned char debug)
{
    static char str[MAX_STR_SIZE];

    strncpy(str, "", sizeof(str));

    snprintf(str, sizeof(str), "0x%x/0x%x",
        TC_U32_USERHTID(num), TC_U32_HASH(num));

    return((const char *)str);
}
