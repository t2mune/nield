/*
 * tcmsg_filter.c - traffic control filter message parser
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

/*
 * parse traffic control filter messages
 */
int parse_tcmsg_filter(struct nlmsghdr *nlh)
{
    struct tcmsg *tcm;
    int tcm_len;
    struct rtattr *tca[__TCA_MAX];
    char msg[MAX_MSG_SIZE] = "";
    char *mp = msg;
    char ifname[IFNAMSIZ];
    char handle[MAX_STR_SIZE] = "";
    char kind[IFNAMSIZ] = "(unknown)";
    char proto[MAX_STR_SIZE];
    int log_opts = get_log_opts();

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get tcmsg */
    tcm_len = NLMSG_PAYLOAD(nlh, 0);
    if(tcm_len < sizeof(*tcm)) {
        rec_log("error: %s: tcmsg: length too short", __func__);
        return(1);
    }
    tcm = (struct tcmsg *)NLMSG_DATA(nlh);

    /* parse traffic control message attributes */
    parse_tc(tca, nlh);

    /* debug tcmsg */
    if(log_opts & L_DEBUG)
        debug_tcmsg(0, nlh, tcm, tca, tcm_len);

    /* kind of message */
    switch(nlh->nlmsg_type) {
        case RTM_NEWTFILTER:
            mp = add_log(msg, mp, "tc filter added: ");
            break;
        case RTM_DELTFILTER:
            mp = add_log(msg, mp, "tc filter deleted: ");
            break;
        default:
            rec_log("error: %s: nlmsg_type: unknown message", __func__);
            return(1);
    }

    /* get interface name */
    if_indextoname_from_lists(tcm->tcm_ifindex, ifname);

    mp = add_log(msg, mp, "interface=%s ", ifname); 

    /* get qdisc kind */
    if(tca[TCA_KIND])
        strncpy(kind, (char *)RTA_DATA(tca[TCA_KIND]), sizeof(kind));

    /* get filter handle */
    if(!strncmp(kind, "u32", sizeof(kind)))
        parse_u32_handle(handle, sizeof(handle), tcm->tcm_handle);
    else
        snprintf(handle, sizeof(handle), "0x%x", tcm->tcm_handle);

    mp = add_log(msg, mp, "handle=%s ", handle);

    /* get priority */
    mp = add_log(msg, mp, "priority=%u ", TC_H_MAJ(tcm->tcm_info)>>16);

    /* get priority */
    strncpy(proto, conv_eth_p(ntohs(TC_H_MIN(tcm->tcm_info)), 0), sizeof(proto));
    if(strlen(proto))
        mp = add_log(msg, mp, "protocol=%s ", proto);
    else
        mp = add_log(msg, mp, "protocol=0x%04x ", ntohs(TC_H_MIN(tcm->tcm_info)));

    /* get filter options */
    mp = add_log(msg, mp, "filter=%s ", kind);

    if(tca[TCA_OPTIONS]) {
        if(!strncmp(kind, "u32", sizeof(kind))) {
            if(parse_tca_options_u32(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#if HAVE_DECL_TCA_RSVP_UNSPEC
        } else if(!strncmp(kind, "rsvp", sizeof(kind))) {
            if(parse_tca_options_rsvp(msg, &mp, tcm, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#endif
        } else if(!strncmp(kind, "route", sizeof(kind))) {
            if(parse_tca_options_route(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
        } else if(!strncmp(kind, "fw", sizeof(kind))) {
            if(parse_tca_options_fw(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#if HAVE_DECL_TCA_TCINDEX_UNSPEC
        } else if(!strncmp(kind, "tcindex", sizeof(kind))) {
            if(parse_tca_options_tcindex(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#endif
#if HAVE_DECL_TCA_FLOW_UNSPEC
        } else if(!strncmp(kind, "flow", sizeof(kind))) {
            if(parse_tca_options_flow(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#endif
        } else if(!strncmp(kind, "basic", sizeof(kind))) {
            if(parse_tca_options_basic(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#if HAVE_DECL_TCA_CGROUP_UNSPEC
        } else if(!strncmp(kind, "cgroup", sizeof(kind))) {
            if(parse_tca_options_cgroup(msg, &mp, tca[TCA_OPTIONS]))
                return(1);
            return(0);
#endif
        }
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * parse attribute TCA_*_CLASSID
 */
int parse_tca_classid(char *msg, char **mp, struct rtattr *tca)
{
    char classid[MAX_STR_SIZE] = "";

    if(RTA_PAYLOAD(tca) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    parse_tc_handle(classid, sizeof(classid), *(unsigned *)RTA_DATA(tca));
    *mp = add_log(msg, *mp, "classid=%s ", classid);

    return(0);
}

/*
 * parse attribute TCA_*_INDEV
 */
int parse_tca_indev(char *msg, char **mp, struct rtattr *tca)
{
    char name[IFNAMSIZ];

    if(!RTA_PAYLOAD(tca)) {
        rec_log("error: %s: no payload", __func__);
        return(1);
    } else if(RTA_PAYLOAD(tca) > sizeof(name)) {
        rec_log("error: %s: payload too long", __func__);
        return(1);
    }
    strncpy(name, (char *)RTA_DATA(tca), sizeof(name));
    *mp = add_log(msg, *mp, "in=%s ", name);

    return(0);
}

/*
 * parse attribute TCA_*_MASK
 */
int parse_tca_mask(char *msg, char **mp, struct rtattr *tca)
{
    if(RTA_PAYLOAD(tca) < sizeof(unsigned)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    *mp = add_log(msg, *mp, "mask=0x%08x ", *(unsigned *)RTA_DATA(tca));

    return(0);
}

/*
 * parse filter handle
 */
void parse_u32_handle(char *p, int len, unsigned handle)
{
    if(TC_U32_HTID(handle))
        APPEND_SNPRINTF(rc, p, len, "%x", TC_U32_HTID(handle)>>20);

    APPEND_SNPRINTF(rc, p, len, ":");

    if(TC_U32_HASH(handle))
        APPEND_SNPRINTF(rc, p, len, "%x", TC_U32_HASH(handle));

    APPEND_SNPRINTF(rc, p, len, ":");

    if(TC_U32_NODE(handle))
        APPEND_SNPRINTF(rc, p, len, "%x", TC_U32_NODE(handle));
}

/*
 * parse attribute TCA_EMATCH_*
 */
int parse_tca_ematch(char *msg, char *mp, struct rtattr *tca)
{
    struct rtattr *em_tree[__TCA_EMATCH_TREE_MAX];
    int num = -1;

    parse_nested_rtattr(em_tree, TCA_EMATCH_TREE_MAX, tca);

    if(em_tree[TCA_EMATCH_TREE_HDR])
        if(parse_tca_ematch_tree_hdr(em_tree[TCA_EMATCH_TREE_HDR], &num))
            return(1);

    if(em_tree[TCA_EMATCH_TREE_LIST])
        if(parse_tca_ematch_tree_list(msg, mp, em_tree[TCA_EMATCH_TREE_LIST], num))
            return(1);

    return(0);
}

/*
 * parse attribute TCA_EMATCH_TREE_HDR
 */
int parse_tca_ematch_tree_hdr(struct rtattr *em_tree, int *num)
{
    struct tcf_ematch_tree_hdr *hdr;

    if(RTA_PAYLOAD(em_tree) < sizeof(*hdr)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    hdr = (struct tcf_ematch_tree_hdr *)RTA_DATA(em_tree);
    *num = hdr->nmatches;

    return(0);
}

/*
 * parse attribute TCA_EMATCH_TREE_LIST
 */
int parse_tca_ematch_tree_list(char *msg, char *mp, struct rtattr *em_tree, int num)
{
    struct rtattr *em_list[num+1];
    struct tcf_ematch_hdr *hdr;
    int i;
    char *mp_tmp = mp;

    parse_nested_rtattr(em_list, num, em_tree);

    /* no exist em_list[0] */
    for(i = 1; i < num + 1; i++, mp = mp_tmp) {
        if(!em_list[i])
            return(0);

        if(RTA_PAYLOAD(em_list[i]) < sizeof(*hdr)) {
            rec_log("error: %s: payload too short", __func__);
            return(1);
        }
        hdr = (struct tcf_ematch_hdr *)RTA_DATA(em_list[i]);
        mp = add_log(msg, mp, "ematch=%s ", conv_tcf_em_kind(hdr->kind, 0));

        /* use (char*)hdr in order to count by one byte */
        switch(hdr->kind) {
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
            case TCF_EM_CMP:
                if(parse_ematch_cmp(msg, mp, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr)))
                    return(1);
                break;
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_NBYTE_H
            case TCF_EM_NBYTE:
                if(parse_ematch_nbyte(msg, mp, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr)))
                    return(1);
                break;
#endif
            case TCF_EM_U32:
                if(parse_ematch_u32(msg, mp, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr)))
                    return(1);
                break;
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
            case TCF_EM_META:
                if(parse_ematch_meta(msg, mp, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr)))
                    return(1);
                break;
#endif
            /* not implemented yet
            case TCF_EM_TEXT:
            case TCF_EM_VLAN:
            case TCF_EM_CANID:
            case TCF_EM_IPSET:
            */
            default:
                rec_log("%s", msg);
        }
    }

    return(0);
}

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
/*
 * parse ematch cmp
 */
int parse_ematch_cmp(char *msg, char *mp, void *p, int len)
{
    struct tcf_em_cmp *cmp;

    if(len < sizeof(struct tcf_em_cmp)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    cmp = (struct tcf_em_cmp *)p;

    mp = add_log(msg, mp,
        "layer=%d align=%s flag=%s operand=%s value=0x%08x mask=0x%08x offset=%hu ",
        cmp->layer, conv_tcf_em_align(cmp->align, 0),
        cmp->flags ? "trans" : "none", conv_tcf_em_opnd(cmp->opnd, 0),
        cmp->val, cmp->mask, cmp->off);

    rec_log("%s", msg);

    return(0);
}
#endif

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_NBYTE_H
/*
 * parse ematch nbyte
 */
int parse_ematch_nbyte(char *msg, char *mp, void *p, int len)
{
    struct tcf_em_nbyte *nbyte;
    int i;
    char *data;

    if(len < sizeof(struct tcf_em_nbyte)) {
        rec_log("error: %s: tcf_em_nbyte: payload too short", __func__);
        return(1);
    }
    nbyte = (struct tcf_em_nbyte *)p;

    if(len - sizeof(*nbyte) < nbyte->len) {
        rec_log("error: %s: len: payload too short", __func__);
        return(1);
    }

    data = (char *)nbyte + sizeof(*nbyte);

    mp = add_log(msg, mp, "layer=%d ", nbyte->layer);

    for(i = 0; i < nbyte->len; i++) {
        if(!i)
            mp = add_log(msg, mp, "value=\"");

        mp = add_log(msg, mp, "%c", isprint(data[i]) ? data[i] : '.');

        if(nbyte->len - i == 1)
            mp = add_log(msg, mp, "\"");
    }

    mp = add_log(msg, mp, " offset=%hu ", nbyte->off);

    rec_log("%s", msg);

    return(0);
}
#endif

/*
 * parse ematch u32
 */
int parse_ematch_u32(char *msg, char *mp, void *p, int len)
{
    struct tc_u32_key *key;

    if(len < sizeof(*key)) {
        rec_log("error: %s: payload too short", __func__);
        return(1);
    }
    key = (struct tc_u32_key *)p;

    mp = add_log(msg, mp, "value=0x%08x mask=0x%08x offset=%d offmask=0x%08x",
        ntohl(key->val), ntohl(key->mask), key->off, key->offmask);

    rec_log("%s", msg);

    return(0);
}

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
/*
 * parse ematch meta
 */
int parse_ematch_meta(char *msg, char *mp, void *p, int len)
{
    struct rtattr *meta[__TCA_EM_META_MAX];
    struct tcf_meta_hdr *hdr = NULL;
    struct tcf_meta_val *left = NULL, *right = NULL;

    parse_rtattr(meta, TCA_EM_META_MAX, p, len);

    if(meta[TCA_EM_META_HDR]) {
        if(RTA_PAYLOAD(meta[TCA_EM_META_HDR]) < sizeof(*hdr)) {
            rec_log("error: %s: TCA_EM_META_HDR: payload too short", __func__);
            return(1);
        }
        hdr = (struct tcf_meta_hdr *)RTA_DATA(meta[TCA_EM_META_HDR]);
        left = &(hdr->left);
        right = &(hdr->right);
    } else {
        rec_log("error: %s: TCA_EM_META_HDR: no attribute", __func__);
        return(1);
    }

    mp = add_log(msg, mp, "match=(");

    if(meta[TCA_EM_META_LVALUE]) {
        if(parse_tca_em_meta_value(msg, &mp, left, meta[TCA_EM_META_LVALUE]))
            return(1);
    } else {
        rec_log("error: %s: TCA_EM_META_LVALUE: no attribute", __func__);
        return(1);
    }

    mp = add_log(msg, mp, "%s ", conv_tcf_em_opnd(left->op, 0));

    if(meta[TCA_EM_META_RVALUE]) {
        if(parse_tca_em_meta_value(msg, &mp, right, meta[TCA_EM_META_RVALUE]))
            return(1);
    } else {
        rec_log("error: %s: TCA_EM_META_RVALUE: no attribute", __func__);
        return(1);
    }
    mp = add_log(msg, mp, ") ");

    rec_log("%s", msg);

    return(0);
}

/*
 * parse ematch meta value
 */
int parse_tca_em_meta_value(char *msg, char **mp, struct tcf_meta_val *val, struct rtattr *meta)
{
    int id = TCF_META_ID(val->kind);
    int type = TCF_META_TYPE(val->kind);
    char *data = (char *)RTA_DATA(meta);
    int i;

    if(id != TCF_META_ID_VALUE) {
        *mp = add_log(msg, *mp, "%s ", conv_tcf_meta_id(id, 0));
        if(val->shift)
            *mp = add_log(msg, *mp, "shift %d ", val->shift);
        if(type == TCF_META_TYPE_INT && *(unsigned *)RTA_DATA(meta)) {
            if(RTA_PAYLOAD(meta) < sizeof(__u32)) {
                rec_log("error: %s: payload too short", __func__);
                return(1);
            }
            *mp = add_log(msg, *mp, "mask 0x%08x ", *(unsigned *)RTA_DATA(meta));
        }

        return(0);
    }

    switch(type) {
        case TCF_META_TYPE_VAR:
            for(i = 0; i < RTA_PAYLOAD(meta); i++)
                *mp = add_log(msg, *mp, "%c", isprint(data[i]) ? data[i] : '.');
            break;
        case TCF_META_TYPE_INT:
            if(RTA_PAYLOAD(meta) < sizeof(__u32)) {
                rec_log("error: %s: payload too short", __func__);
                return(1);
            }
            *mp = add_log(msg, *mp, "%d", *(int *)RTA_DATA(meta));
            break;
        default:
            rec_log("error: %s: unknown type(%d)", __func__, type);
            return(1);
    }

    return(0);
}
#endif

/*
 * debug attribute TCA_EMATCH_*
 */
void debug_tca_ematch(int lev, struct rtattr *tca, const char *name)
{
    struct rtattr *em_tree[__TCA_EMATCH_TREE_MAX];
    int num = -1;

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tca->rta_len));

    parse_nested_rtattr(em_tree, TCA_EMATCH_TREE_MAX, tca);

    if(em_tree[TCA_EMATCH_TREE_HDR])
        num = debug_tca_ematch_tree_hdr(lev+1, em_tree[TCA_EMATCH_TREE_HDR],
            "TCA_EMATCH_TREE_HDR");

    if(em_tree[TCA_EMATCH_TREE_LIST])
        debug_tca_ematch_tree_list(lev+1, em_tree[TCA_EMATCH_TREE_LIST],
            "TCA_EMATCH_TREE_LIST", num);
}

/*
 * debug attribute TCA_EMATCH_TREE_HDR
 */
int debug_tca_ematch_tree_hdr(int lev, struct rtattr *em_tree, const char *name)
{
    struct tcf_ematch_tree_hdr *hdr;

    if(debug_rta_len_chk(lev, em_tree, name, sizeof(*hdr)))
        return(-1);

    hdr = (struct tcf_ematch_tree_hdr *)RTA_DATA(em_tree);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(em_tree->rta_len));
    rec_dbg(lev, "    [ tcf_ematch_tree_hdr(%d) ]", sizeof(*hdr));
    rec_dbg(lev, "        nmatches(%d): %hu", sizeof(hdr->nmatches), hdr->nmatches);
    rec_dbg(lev, "        progid(%d): %hu", sizeof(hdr->progid), hdr->progid);

    return(hdr->nmatches);
}

/*
 * debug attribute TCA_EMATCH_TREE_LIST
 */
void debug_tca_ematch_tree_list(int lev, struct rtattr *em_tree, const char *name, int num)
{
    struct rtattr *em_list[num+1];
    struct tcf_ematch_hdr *hdr;
    int i;

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(em_tree->rta_len));

    parse_nested_rtattr(em_list, num, em_tree);

    /* no exist em_list[0] */
    for(i = 1; i < num + 1; i++) {
        if(!em_list[i])
            return;

        if(RTA_PAYLOAD(em_list[i]) < sizeof(*hdr)) {
            rec_dbg(lev+1, "[ tcf_ematch_hdr[%d](%d) ] -- payload too short --",
                i, sizeof(*hdr));
            return;
        }
        hdr = (struct tcf_ematch_hdr *)RTA_DATA(em_list[i]);

        rec_dbg(lev+1, "[ tcf_ematch_hdr[%d](%d) ]", i, sizeof(*hdr));
        rec_dbg(lev+1, "    matchid(%d): %hu", sizeof(hdr->matchid), hdr->matchid);
        rec_dbg(lev+1, "    kind(%d): %hu(%s)",
            sizeof(hdr->kind), hdr->kind, conv_tcf_em_kind(hdr->kind, 1));
        rec_dbg(lev+1, "    flags(%d): %hu(%s)",
            sizeof(hdr->flags), hdr->flags, conv_tcf_em_flag(hdr->flags, 1));
        rec_dbg(lev+1, "    pad(%d): %hu", sizeof(hdr->pad), hdr->pad);

        /* use (char*)hdr in order to count by one byte */
        switch(hdr->kind) {
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
            case TCF_EM_CMP:
                debug_ematch_cmp(lev+1, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr));
                break;
#endif
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_NBYTE_H
            case TCF_EM_NBYTE:
                debug_ematch_nbyte(lev+1, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr));
                break;
#endif
            case TCF_EM_U32:
                debug_ematch_u32(lev+1, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr));
                break;
#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
            case TCF_EM_META:
                debug_ematch_meta(lev+1, (char *)hdr + sizeof(*hdr),
                    RTA_PAYLOAD(em_list[i]) - sizeof(*hdr));
                break;
#endif
            /* not implemented yet
            case TCF_EM_TEXT:
            case TCF_EM_VLAN:
            case TCF_EM_CANID:
            case TCF_EM_IPSET:
            */
            default:
                break;
        }
    }
}

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
/*
 * debug ematch cmp
 */
void debug_ematch_cmp(int lev, void *p, int len)
{
    struct tcf_em_cmp *cmp;

    if(len < sizeof(struct tcf_em_cmp)) {
        rec_dbg(lev, "[ tcf_em_cmp(%d) ] -- payload too short --", len);
        return;
    }
    cmp = (struct tcf_em_cmp *)p;

    rec_dbg(lev, "[ tcf_em_cmp(%d) ]", len);
    rec_dbg(lev, "    val(%d): 0x%08x", sizeof(cmp->val), cmp->val);
    rec_dbg(lev, "    mask(%d): 0x%08x", sizeof(cmp->mask), cmp->mask);
    rec_dbg(lev, "    off(%d): %hu", sizeof(cmp->off), cmp->off);
    rec_dbg(lev, "    align:4(%d): 0x%x(%s)",
        sizeof(__u8), cmp->align, conv_tcf_em_align(cmp->align, 1));
    rec_dbg(lev, "    flags:4(%d): 0x%x(%s)",
        sizeof(__u8), cmp->flags, TCF_EM_CMP_TRANS ? "TRANS" : "none");
    rec_dbg(lev, "    layer:4(%d): 0x%x", sizeof(__u8), cmp->layer);
    rec_dbg(lev, "    opnd:4(%d): 0x%x(%s)",
        sizeof(__u8), cmp->opnd, conv_tcf_em_opnd(cmp->opnd, 1));
}
#endif

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_NBYTE_H
/*
 * debug ematch nbyte
 */
void debug_ematch_nbyte(int lev, void *p, int len)
{
    struct tcf_em_nbyte *nbyte;
    int i;
    char *data;

    if(len < sizeof(struct tcf_em_nbyte)) {
        rec_dbg(lev, "[ tcf_em_nbyte(%d) ] -- payload too short --", len);
        return;
    }
    nbyte = (struct tcf_em_nbyte *)p;

    rec_dbg(lev, "[ tcf_em_nbyte(%d) ]", len);
    rec_dbg(lev, "    off(%d): %hu", sizeof(nbyte->off), nbyte->off);
    rec_dbg(lev, "    len:12(%d): %hu", sizeof(__u16), nbyte->len);
    rec_dbg(lev, "    layer:4(%d): %hu", sizeof(__u8), nbyte->layer);

    if(len - sizeof(*nbyte) < nbyte->len) {
        rec_dbg(lev, "    data(%d): -- payload too short --", nbyte->len);
        return;
    }

    data = (char *)nbyte + sizeof(*nbyte);

    for(i = 0; i < nbyte->len; i++)
        data[i] = isprint(data[i]) ? data[i] : '.';

    data[i] = '\0';

    rec_dbg(lev, "    data(%d): %s", nbyte->len, data);
}
#endif

/*
 * debug ematch u32
 */
void debug_ematch_u32(int lev, void *p, int len)
{
    struct tc_u32_key *key;

    if(len < sizeof(*key)) {
        rec_dbg(lev, "[ tc_u32_key(%d) ] -- payload too short --", len);
        return;
    }
    key = (struct tc_u32_key *)p;

    rec_dbg(lev, "[ tc_u32_key(%d) ]", sizeof(*key));
    rec_dbg(lev, "    mask(%d): 0x%08x", sizeof(key->mask), key->mask); /* AND */
    rec_dbg(lev, "    val(%d): 0x%08x", sizeof(key->val), key->val); /* XOR */
    rec_dbg(lev, "    off(%d): %d", sizeof(key->off), key->off); /* Offset */
    rec_dbg(lev, "    offmask(%d): 0x%08x", sizeof(key->offmask), key->offmask);
}

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
/*
 * debug ematch meta
 */
void debug_ematch_meta(int lev, void *p, int len)
{
    struct rtattr *meta[__TCA_EM_META_MAX];
    struct tcf_meta_hdr *hdr = NULL;

    parse_rtattr(meta, TCA_EM_META_MAX, p, len);

    if(meta[TCA_EM_META_HDR])
        hdr = debug_tca_em_meta_hdr(lev, meta[TCA_EM_META_HDR],
            "TCA_EM_META_HDR");

    if(!hdr)
        return;

    if(meta[TCA_EM_META_LVALUE])
        debug_tca_em_meta_value(lev, meta[TCA_EM_META_LVALUE],
            "TCA_EM_META_LVALUE", &(hdr->left));

    if(meta[TCA_EM_META_RVALUE])
        debug_tca_em_meta_value(lev, meta[TCA_EM_META_RVALUE],
            "TCA_EM_META_RVALUE", &(hdr->right));
}

/*
 * debug attribute TCA_EM_META_HDR
 */
struct tcf_meta_hdr *debug_tca_em_meta_hdr(int lev, struct rtattr *meta, const char *name)
{
    struct tcf_meta_hdr *hdr;
    struct tcf_meta_val *left, *right;

    if(debug_rta_len_chk(lev, meta, name, sizeof(*hdr)))
        return(NULL);

    hdr = (struct tcf_meta_hdr *)RTA_DATA(meta);
    left = &(hdr->left);
    right = &(hdr->right);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(meta->rta_len));
    rec_dbg(lev, "    [ tcf_meta_hdr(%d) ]", sizeof(*hdr));
    rec_dbg(lev, "        [ tcf_meta_val left(%d) ]", sizeof(*left));
    rec_dbg(lev, "            kind(%d): 0x%04x(%s,%s)",
        sizeof(left->kind), left->kind,
        conv_tcf_meta_type(TCF_META_TYPE(left->kind), 1),
        conv_tcf_meta_id(TCF_META_ID(left->kind), 1));
    rec_dbg(lev, "            shift(%d): %d", sizeof(left->shift), left->shift);
    rec_dbg(lev, "            op(%d): %d(%s)",
        sizeof(left->op), left->op, conv_tcf_em_opnd(left->op, 1));
    rec_dbg(lev, "        [ tcf_meta_val right(%d) ]", sizeof(*right));
    rec_dbg(lev, "            kind(%d): 0x%04x(%s,%s)",
        sizeof(right->kind), right->kind,
        conv_tcf_meta_type(TCF_META_TYPE(right->kind), 1),
        conv_tcf_meta_id(TCF_META_ID(right->kind), 1));
    rec_dbg(lev, "            shift(%d): %d", sizeof(right->shift), right->shift);
    rec_dbg(lev, "            op(%d): %d(%s)",
        sizeof(right->op), right->op, conv_tcf_em_opnd(right->op, 1));

    return(hdr);
}

/*
 * debug attribute TCA_EM_META_LVALUE
 */
void debug_tca_em_meta_value(int lev, struct rtattr *meta, const char *name, struct tcf_meta_val *p)
{
    int i, type, len = RTA_PAYLOAD(meta) + 1;
    char *data = (char *)RTA_DATA(meta), *val;

    type = TCF_META_TYPE(p->kind);

    switch(type) {
        case TCF_META_TYPE_VAR:
            val = malloc(len);
            if(!val) {
                rec_dbg(lev, "%s(%hu): -- %s --",
                    name, RTA_ALIGN(meta->rta_len), strerror(errno));
                return;
            }
            memset(val, 0, len);

            for(i = 0; i < RTA_PAYLOAD(meta); i++)
                val[i] = isprint(data[i]) ? data[i] : '.';
            data[i] = '\0';

            rec_dbg(lev, "%s(%hu): %s",
                name, RTA_ALIGN(meta->rta_len), data);

            free(val);
            break;
        case TCF_META_TYPE_INT:
            if(RTA_PAYLOAD(meta) < sizeof(__u32)) {
                rec_dbg(lev, "%s(%hu): -- payload too short --",
                    name, RTA_ALIGN(meta->rta_len));
                return;
            }
            rec_dbg(lev, "%s(%hu): %d",
                name, RTA_ALIGN(meta->rta_len), *(int *)RTA_DATA(meta));
            break;
        default:
            rec_dbg(lev, "%s(%hu): -- unknown type(%d) --",
                name, RTA_ALIGN(meta->rta_len), type);
            return;
    }

}
#endif

/*
 *  convert TC_U32_* flags from number to string
 */
void conv_tc_u32_flags(int flags, char *flags_list, int len, unsigned char debug)
{
    if(!flags) {
        strncpy(flags_list, debug ? "NONE" : "none", len);
        return;
    }
#define _TC_U32_FLAGS(s1, s2) \
    if((flags & TC_U32_##s1) && (len - strlen(flags_list) - 1 > 0)) \
        (flags &= ~ TC_U32_##s1) ? \
            strncat(flags_list, debug ? #s1 "," : #s2 ",", \
                len - strlen(flags_list) - 1) : \
            strncat(flags_list, debug ? #s1 : #s2, \
                len - strlen(flags_list) - 1);
    _TC_U32_FLAGS(TERMINAL, terminal);
    _TC_U32_FLAGS(OFFSET, offset);
    _TC_U32_FLAGS(VAROFFSET, varoffset);
    _TC_U32_FLAGS(EAT, eat);
#undef _TC_U32_FLAGS
    if(!strlen(flags_list))
        strncpy(flags_list, debug ? "UNKNOWN" : "unknown", len);
}

/*
 * convert ETH_P_* protocol from number to string
 */
const char *conv_eth_p(unsigned short proto, unsigned char debug)
{
#define _ETH_P(s1, s2) \
    if(proto == ETH_P_##s1) \
        return(debug ? #s1 : #s2);
    _ETH_P(LOOP, loop)
    _ETH_P(PUP, pup)
    _ETH_P(PUPAT, PUPAT)
    _ETH_P(IP, ip)
    _ETH_P(X25, x25)
    _ETH_P(ARP, arp)
    _ETH_P(BPQ, bpq)
    _ETH_P(IEEEPUP, ieeepup)
    _ETH_P(IEEEPUPAT, ieeeupat)
    _ETH_P(DEC, dec)
    _ETH_P(DNA_DL, dna_dl)
    _ETH_P(DNA_RC, dna_rc)
    _ETH_P(DNA_RT, dna_rt)
    _ETH_P(LAT, lat)
    _ETH_P(DIAG, diag)
    _ETH_P(CUST, cust)
    _ETH_P(SCA, sca)
#ifdef ETH_P_TEB
    _ETH_P(TEB, teb)
#endif
    _ETH_P(RARP, rarp)
    _ETH_P(ATALK, atalk)
    _ETH_P(AARP, aarp)
    _ETH_P(8021Q, 802.1q)
    _ETH_P(IPX, ipx)
    _ETH_P(IPV6, ipv6)
#ifdef ETH_P_PAUSE
    _ETH_P(PAUSE, pause)
#endif
    _ETH_P(SLOW, slow)
    _ETH_P(WCCP, wccp)
    _ETH_P(PPP_DISC, ppp_disc)
    _ETH_P(PPP_SES, ppp_ses)
    _ETH_P(MPLS_UC, mpls_uc)
    _ETH_P(MPLS_MC, mpls_mc)
    _ETH_P(ATMMPOA, atmmpoa)
#ifdef ETH_P_LINK_CTL
    _ETH_P(LINK_CTL, link_ctl)
#endif
    _ETH_P(ATMFATE, atmfate)
#ifdef ETH_P_PAE
    _ETH_P(PAE, pae)
#endif
    _ETH_P(AOE, aoe)
#ifdef ETH_P_8021AD
    _ETH_P(8021AD, 802.1ad)
#endif
#ifdef ETH_P_802_EX1
    _ETH_P(802_EX1, 802_ex1)
#endif
    _ETH_P(TIPC, tipc)
#ifdef ETH_P_8021AH
    _ETH_P(8021AH, 802.1ah)
#endif
#ifdef ETH_P_1588
    _ETH_P(1588, 1588)
#endif
    _ETH_P(FCOE, fcoe)
#ifdef ETH_P_TDLS
    _ETH_P(TDLS, tdls)
#endif
    _ETH_P(FIP, fip)
#ifdef ETH_P_QINQ1
    _ETH_P(QINQ1, q-in-q1)
#endif
#ifdef ETH_P_QINQ2
    _ETH_P(QINQ2, q-in-q2)
#endif
#ifdef ETH_P_QINQ3
    _ETH_P(QINQ3, q-in-q3)
#endif
#ifdef ETH_P_EDSA
    _ETH_P(EDSA, edsa)
#endif
#ifdef ETH_P_AF_IUCV
    _ETH_P(AF_IUCV, af_iucv)
#endif
    _ETH_P(802_3, 802_3)
    _ETH_P(AX25, ax25)
    _ETH_P(ALL, all)
    _ETH_P(802_2, 802_2)
    _ETH_P(SNAP, snap)
    _ETH_P(DDCMP, ddcmp)
    _ETH_P(WAN_PPP, wan_ppp)
    _ETH_P(PPP_MP, ppp_mp)
    _ETH_P(LOCALTALK, localtalk)
#ifdef ETH_P_CAN
    _ETH_P(CAN, can)
#endif
#ifdef ETH_P_CANFD
    _ETH_P(CANFD, canfd)
#endif
    _ETH_P(PPPTALK, ppptalk)
    _ETH_P(TR_802_2, tr_802_2)
    _ETH_P(MOBITEX, mobitex)
    _ETH_P(CONTROL, control)
    _ETH_P(IRDA, irda)
    _ETH_P(ECONET, econet)
    _ETH_P(HDLC, hdlc)
    _ETH_P(ARCNET, arcnet)
#ifdef ETH_P_DSA
    _ETH_P(DSA, dsa)
#endif
#ifdef ETH_P_TRAILER
    _ETH_P(TRAILER, trailer)
#endif
#ifdef ETH_P_PHONET
    _ETH_P(PHONET, phonet)
#endif
#ifdef ETH_P_IEEE802154
    _ETH_P(IEEE802154, ieee802154)
#endif
#ifdef ETH_P_CAIF
    _ETH_P(CAIF, caif)
#endif
#undef _ETH_P
    return((const char *)(debug ? "UNKNOWN" : "unknown"));
}

/*
 * convert TCF_EM_* kind from number to string
 */
const char *conv_tcf_em_kind(int kind, unsigned char debug)
{
#define _TCF_EM(s1, s2) \
    if(kind == TCF_EM_##s1) \
        return(debug ? #s1 : #s2);
    _TCF_EM(CONTAINER, container)
    _TCF_EM(CMP, cmp)
    _TCF_EM(NBYTE, nbyte)
    _TCF_EM(U32, u32)
    _TCF_EM(META, meta)
    _TCF_EM(TEXT, text)
#if HAVE_DECL_TCF_EM_VLAN
    _TCF_EM(VLAN, vlan)
#endif
#if HAVE_DECL_TCF_EM_CANID
    _TCF_EM(CANID, canid)
#endif
#if HAVE_DECL_TCF_EM_IPSET
    _TCF_EM(IPSET, ipset)
#endif
#undef _TCF_EM
    return(debug ? "UNKNOWN" : "unknown");
}

/*
 * convert TCF_EM_* flags from number to string
 */
const char *conv_tcf_em_flag(int flag, unsigned char debug)
{
#define _TCF_EM(s1, s2) \
    if(flag == TCF_EM_##s1) \
        return(debug ? #s1 : #s2);
    _TCF_EM(REL_END, end)
    _TCF_EM(REL_AND, and)
    _TCF_EM(REL_OR, or)
    _TCF_EM(INVERT, invert)
    _TCF_EM(SIMPLE, simple)
#undef _TCF_EM
    return(debug ? "UNKNOWN" : "unknown");
}

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_CMP_H
/*
 * convert TCF_EM_ALIGN_* from number to string
 */
const char *conv_tcf_em_align(int align, unsigned char debug)
{
#define _TCF_EM_ALIGN(s1, s2) \
    if(align == TCF_EM_ALIGN_##s1) \
        return(debug ? #s1 : #s2);
    _TCF_EM_ALIGN(U8, u8)
    _TCF_EM_ALIGN(U16, u16)
    _TCF_EM_ALIGN(U32, u32)
#undef _TCF_EM_ALIGN
    return(debug ? "UNKNOWN" : "unknown");
}
#endif

/*
 * convert TCF_EM_OPND_* from number to string
 */
const char *conv_tcf_em_opnd(int opnd, unsigned char debug)
{
#define _TCF_EM_OPND(s1, s2) \
    if(opnd == TCF_EM_OPND_##s1) \
        return(debug ? #s1 : #s2);
    _TCF_EM_OPND(EQ, eq)
    _TCF_EM_OPND(GT, gt)
    _TCF_EM_OPND(LT, lt)
#undef _TCF_EM_OPND
    return(debug ? "UNKNOWN" : "unknown");
}

#ifdef HAVE_LINUX_TC_EMATCH_TC_EM_META_H
/*
 * convert TCF_META_TYPE_* from number to string
 */
const char *conv_tcf_meta_type(int type, unsigned char debug)
{
#define _TCF_META_TYPE(s1, s2) \
    if(type == TCF_META_TYPE_##s1) \
        return(debug ? #s1 : #s2);
    _TCF_META_TYPE(VAR, var)
    _TCF_META_TYPE(INT, int)
#undef _TCF_META_TYPE
    return(debug ? "UNKNOWN" : "unknown");
}

/*
 * convert TCF_META_ID_* from number to string
 */
const char *conv_tcf_meta_id(int id, unsigned char debug)
{
#define _TCF_META_ID(s1, s2) \
    if(id == TCF_META_ID_##s1) \
        return(debug ? #s1 : #s2);
        _TCF_META_ID(VALUE, value)
        _TCF_META_ID(RANDOM, random)
        _TCF_META_ID(LOADAVG_0, loadavg_0)
        _TCF_META_ID(LOADAVG_1, loadavg_1)
        _TCF_META_ID(LOADAVG_2, loadavg_2)
        _TCF_META_ID(DEV, dev)
        _TCF_META_ID(PRIORITY, priority)
        _TCF_META_ID(PROTOCOL, protocol)
        _TCF_META_ID(PKTTYPE, pkttype)
        _TCF_META_ID(PKTLEN, pktlen)
        _TCF_META_ID(DATALEN, datalen)
        _TCF_META_ID(MACLEN, maclen)
        _TCF_META_ID(NFMARK, nfmark)
#if HAVE_DECL_TCA_TCINDEX_UNSPEC
        _TCF_META_ID(TCINDEX, tcindex)
#endif
        _TCF_META_ID(RTCLASSID, rtclassid)
        _TCF_META_ID(RTIIF, rtiif)
        _TCF_META_ID(SK_FAMILY, sk_family)
        _TCF_META_ID(SK_STATE, sk_state)
        _TCF_META_ID(SK_REUSE, sk_reuse)
        _TCF_META_ID(SK_BOUND_IF, sk_bound_if)
        _TCF_META_ID(SK_REFCNT, sk_refcnt)
        _TCF_META_ID(SK_SHUTDOWN, sk_shutdown)
        _TCF_META_ID(SK_PROTO, sk_proto)
        _TCF_META_ID(SK_TYPE, sk_type)
        _TCF_META_ID(SK_RCVBUF, sk_rcvbuf)
        _TCF_META_ID(SK_RMEM_ALLOC, sk_rmem_alloc)
        _TCF_META_ID(SK_WMEM_ALLOC, sk_wmem_alloc)
        _TCF_META_ID(SK_OMEM_ALLOC, sk_omem_alloc)
        _TCF_META_ID(SK_WMEM_QUEUED, sk_wmem_queued)
        _TCF_META_ID(SK_RCV_QLEN, sk_rcv_qlen)
        _TCF_META_ID(SK_SND_QLEN, sk_snd_qlen)
        _TCF_META_ID(SK_ERR_QLEN, sk_err_qlen)
        _TCF_META_ID(SK_FORWARD_ALLOCS, sk_forward_allocs)
        _TCF_META_ID(SK_SNDBUF, sk_sndbug)
        _TCF_META_ID(SK_ALLOCS, sk_allocs)
        /* __TCF_META_ID_SK_ROUTE_CAPS */
        _TCF_META_ID(SK_HASH, sk_hash)
        _TCF_META_ID(SK_LINGERTIME, sk_lingertime)
        _TCF_META_ID(SK_ACK_BACKLOG, sk_ack_backlog)
        _TCF_META_ID(SK_MAX_ACK_BACKLOG, sk_max_ack_backlog)
        _TCF_META_ID(SK_PRIO, sk_prio)
        _TCF_META_ID(SK_RCVLOWAT, sk_rcvlowat)
        _TCF_META_ID(SK_RCVTIMEO, sk_rcvtimeo)
        _TCF_META_ID(SK_SNDTIMEO, sk_sndtimeo)
        _TCF_META_ID(SK_SENDMSG_OFF, sk_sendmsg_off)
        _TCF_META_ID(SK_WRITE_PENDING, sk_write_pending)
        _TCF_META_ID(VLAN_TAG, vlan_tag)
#if HAVE_DECL_TCF_META_ID_RXHASH
        _TCF_META_ID(RXHASH, rxhash)
#endif
#undef _TCF_META_ID
    return(debug ? "UNKNOWN" : "unknown");
}
#endif
