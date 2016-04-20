/*
 * ndmsg.c - neigbor discovery message parser
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

/* top of interface list */
static struct list_head head = {&head, &head};

/*
 * create a neighbor discovery cache list
 */ 
int create_ndlist(struct msghdr *msg)
{
    struct nlmsghdr *nlh;
    int nlh_len;
    struct ndmsg *ndm;
    int ndm_len;
    struct rtattr *nda[__NDA_MAX];
    struct ndlist_entry *ndle;
    int log_opts = get_log_opts();
    int res;

    /* get netlink message header */
    nlh = msg->msg_iov->iov_base;
    nlh_len = msg->msg_iov->iov_len;

    /* parse netlink message header */
    for( ; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
        /* whether netlink message header ends or not */
        if(nlh->nlmsg_type == NLMSG_DONE)
            return(1);
    
        /* debug nlmsghder */
        if(log_opts & L_DEBUG)
            debug_nlmsg(0, nlh);

        /* get ndmsg */
        ndm_len = NLMSG_PAYLOAD(nlh, 0);
        if(ndm_len < sizeof(*ndm)) {
            rec_log("error: %s: ndmsg: length too short", __func__);
            continue;
        }
        ndm = (struct ndmsg *)NLMSG_DATA(nlh);

        /* parse neighbor discovery attributes */
        parse_ndisc(nda, nlh);

        /* debug ndmsg */
        if(log_opts & L_DEBUG)
            debug_ndmsg(0, ndm, nda, ndm_len);

        /* check address family */
        if((ndm->ndm_family != AF_INET) && (ndm->ndm_family != AF_INET6))
            continue;

        /* check address type */
        if(ndm->ndm_type != RTN_UNICAST)
            continue;

        if(ndm->ndm_state == NUD_NOARP)
            continue;

        /* create neighbor discovery list */
        ndle = (struct ndlist_entry *)malloc(sizeof(struct ndlist_entry));
        if(ndle == NULL) {
            rec_log("error: %s: malloc: failed", __func__);
            return(-1);
        }
        memset(ndle, 0, sizeof(struct ndlist_entry));
        strncpy(ndle->lladdr, "none", sizeof(ndle->lladdr));
        list_init(&(ndle->list));

        /* get interface index */
        ndle->ifindex = ndm->ndm_ifindex;

        /* convert interface index to name */
        if_indextoname_from_lists(ndm->ndm_ifindex, ndle->ifname);

        /* get ip address */
        if(nda[NDA_DST]) {
            res = inet_ntop_ifa(ndm->ndm_family, nda[NDA_DST], ndle->ipaddr,
                sizeof(ndle->ipaddr));
            if(res) {
                rec_log("error: %s: NDA_DST(ifindex %d): %s",
                    __func__, ndle->ifindex,
                    (res == 1) ? strerror(errno) : "payload too short");
                free(ndle);
                continue;
            }
        }
    
        /* get link local address */
        if(nda[NDA_LLADDR]) {
            res = arphrd_ntop(ARPHRD_ETHER, nda[NDA_LLADDR], ndle->lladdr,
                sizeof(ndle->lladdr));
            if(res) {
                rec_log("error: %s: NDA_LLADDR(ifindex %d): %s",
                    __func__, ndle->ifindex,
                    (res == 1) ? strerror(errno) : "payload too short");
                free(ndle);
                continue;
            }
        }

        /* add neighbor discovery cache list */
        list_add(&(ndle->list), &head);
    }

    return(0);
}

/*
 * print a neighbor discovery cache list
 */ 
void print_ndlist(void)
{
    struct list_head *l;
    FILE *ndlist;

    ndlist = fopen(NDLIST_FILE, "w");
    if(ndlist == NULL) {
        rec_log("error: %s: can't open ndlist file(%s)", __func__, NDLIST_FILE);
        return;
    }
    fprintf(ndlist, "\n");
    fprintf(ndlist, "*********************************************************************\n");
    fprintf(ndlist, "[ neighbor list ]\n");

    list_for_each(l, &head) {
        struct ndlist_entry *e;

        e = list_entry(l, struct ndlist_entry, list);

        fprintf(ndlist, "ifindex: %d, ", e->ifindex);
        fprintf(ndlist, "ifname: %s, ", e->ifname);
        fprintf(ndlist, "ipaddr: %s, ", e->ipaddr);
        fprintf(ndlist, "lladdr: %s\n", e->lladdr);
    }

    fclose(ndlist);
}

/*
 * search an entry in a neighbor discovery cache list
 */ 
static inline struct ndlist_entry *search_ndlist(char *ipa, unsigned ifi)
{
    struct list_head *l;

    list_for_each(l, &head) {
        struct ndlist_entry *e;

        e = list_entry(l, struct ndlist_entry, list);
        if(!memcmp(ipa, &(e->ipaddr), sizeof(e->ipaddr)) && ifi == e->ifindex)
            return e;
    }

    return(NULL);
}

/*
 * add a neighbor discovery cache to a list
 */
static inline void add_ndlist_entry(struct list_head *l)
{
    list_init(l);
    list_add(l, &head);
}

/*
 * [not in use]
 * delete an entry in a interface list entry
 */
static inline void del_iflist_entry(char *ipa)
{
    struct list_head *l, *n;

    list_for_each_safe(l, n, &head) {
        struct ndlist_entry *e;

        e = list_entry(l, struct ndlist_entry, list);
        if(!memcmp(ipa, &(e->ipaddr), sizeof(e->ipaddr))) {
            list_del(l);
            free(e);
        }
    }
}

/*
 * parse neighbor discovery message
 */
int parse_ndmsg(struct nlmsghdr *nlh)
{
    struct ndmsg *ndm;
    int ndm_len;
    struct rtattr *nda[__NDA_MAX];
    struct ndlist_entry *ndle_tmp;
    char ndm_type[MAX_STR_SIZE] = "";
    int log_opts = get_log_opts();
    int msg_opts = get_msg_opts();
    int res;

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get ndmsg */
    ndm_len = NLMSG_PAYLOAD(nlh, 0);
    if(ndm_len < sizeof(*ndm)) {
        rec_log("error: %s: ndmsg: length too short", __func__);
        return(1);
    }
    ndm = (struct ndmsg *)NLMSG_DATA(nlh);

    /* parse neighbor discovery attributes */
    parse_ndisc(nda, nlh);

    /* debug ndmsg */
    if(log_opts & L_DEBUG)
        debug_ndmsg(0, ndm, nda, ndm_len);

    /* check address family */
    if(ndm->ndm_family == AF_INET) {
        if((msg_opts & M_IPV4) || !(msg_opts & M_IPV6))
            strcpy(ndm_type, "arp cache");
        else
            return(1);
    } else if(ndm->ndm_family == AF_INET6) {
        if((msg_opts & M_IPV6) || !(msg_opts & M_IPV4))
            strcpy(ndm_type, "ndp cache");
        else
            return(1);
    } else {
        return(1);
    }

    /* unicast only */
    if(ndm->ndm_type != RTN_UNICAST)
        return(1);

    if(ndm->ndm_state == NUD_NOARP)
        return(1);

    /* create temporary neighbor discovery entry */
    ndle_tmp = malloc(sizeof(struct ndlist_entry));
    if(!ndle_tmp) {
        rec_log("error: %s: malloc() failed", __func__);
        return(1);
    }
    memset(ndle_tmp, 0, sizeof(struct ndlist_entry));
    strncpy(ndle_tmp->lladdr, "none", sizeof(ndle_tmp->lladdr));

    /* get interface index */
    ndle_tmp->ifindex = ndm->ndm_ifindex;

    /* convert interface index to name */
    if_indextoname_from_lists((unsigned)ndm->ndm_ifindex, ndle_tmp->ifname);

    /* get ip address */
    if(nda[NDA_DST]) {
        res = inet_ntop_ifa(ndm->ndm_family, nda[NDA_DST], ndle_tmp->ipaddr,
            sizeof(ndle_tmp->ipaddr));
        if(res) {
            rec_log("error: %s: NDA_DST(ifindex %d): %s",
                __func__, ndle_tmp->ifindex,
                (res == 1) ? strerror(errno) : "payload too short");
            free(ndle_tmp);
            return(1);
        }
    }

    /* get link local address */
    if(nda[NDA_LLADDR]) {
        res = arphrd_ntop(ARPHRD_ETHER, nda[NDA_LLADDR], ndle_tmp->lladdr,
            sizeof(ndle_tmp->lladdr));
        if(res) {
            rec_log("error: %s: NDA_LLADDR(ifindex %d): %s",
                __func__, ndle_tmp->ifindex,
                (res == 1) ? strerror(errno) : "payload too short");
            free(ndle_tmp);
            return(1);
        }
    }

    /* logging neighbor discovery message */
    if(nlh->nlmsg_type == RTM_NEWNEIGH)
        parse_rtm_newneigh(ndm_type, ndm, ndle_tmp);
    else if(nlh->nlmsg_type == RTM_DELNEIGH)
        parse_rtm_delneigh(ndm_type, ndm, ndle_tmp);

    return(0);
}

/*
 * parse RTM_NEWNEIGH
 */
int parse_rtm_newneigh(char *ndm_type, struct ndmsg *ndm, struct ndlist_entry *ndle_tmp)
{
    struct ndlist_entry *ndle;

    /* search neighbor discovery entry by ip address */
    ndle = search_ndlist(ndle_tmp->ipaddr, ndle_tmp->ifindex);
    switch(ndm->ndm_state) {
        case NUD_FAILED:
            /* change or add neighbor discovery list entry */
            if(ndle) {
                if(memcmp(ndle->lladdr, ndle_tmp->lladdr, sizeof(ndle->lladdr))) {
                    memcpy(ndle->lladdr, ndle_tmp->lladdr, sizeof(ndle->lladdr));
                    rec_log("%s invalidated: ip=%s mac=%s interface=%s",
                        ndm_type, ndle->ipaddr, ndle->lladdr, ndle->ifname);
                }
                free(ndle_tmp);
            } else {
                add_ndlist_entry(&(ndle_tmp->list));
                rec_log("%s unresolved: ip=%s mac=%s interface=%s",
                    ndm_type, ndle_tmp->ipaddr, ndle_tmp->lladdr, ndle_tmp->ifname);
            }
            break;
        case NUD_PERMANENT:
        case NUD_PROBE:
        case NUD_DELAY:
        case NUD_STALE:
        case NUD_REACHABLE:
            /* change or add neighbor discovery list entry */
            if(ndle) {
                if(memcmp(ndle->lladdr, ndle_tmp->lladdr, sizeof(ndle->lladdr))) {
                    memcpy(ndle->lladdr, ndle_tmp->lladdr, sizeof(ndle->lladdr));
                    rec_log("%s changed: ip=%s mac=%s interface=%s",
                        ndm_type, ndle->ipaddr, ndle->lladdr, ndle->ifname);
                }
                free(ndle_tmp);
            } else {
                add_ndlist_entry(&(ndle_tmp->list));
                rec_log("%s added: ip=%s mac=%s interface=%s",
                    ndm_type, ndle_tmp->ipaddr, ndle_tmp->lladdr, ndle_tmp->ifname);
            }
            break;
        case NUD_NOARP:
        case NUD_INCOMPLETE:
            break;
    }

    return(0);
}

/*
 * parse RTM_DELNEIGH
 */
int parse_rtm_delneigh(char *ndm_type, struct ndmsg *ndm, struct ndlist_entry *ndle_tmp)
{
    struct list_head *l, *n;
    struct ndlist_entry *e;

    switch(ndm->ndm_state) {
        case NUD_FAILED:
        case NUD_INCOMPLETE:
        case NUD_PERMANENT:
        case NUD_REACHABLE:
        case NUD_STALE:
        case NUD_DELAY:
        case NUD_PROBE:
        case NUD_NOARP:
            /* search & delete neighbor discovery entry */
            list_for_each_safe(l, n, &head) {
                e = list_entry(l, struct ndlist_entry, list);
                if(!memcmp(e->ipaddr, ndle_tmp->ipaddr, sizeof(e->ipaddr))) {
                    rec_log("%s deleted: ip=%s mac=%s interface=%s",
                        ndm_type, ndle_tmp->ipaddr, ndle_tmp->lladdr, e->ifname);
                    list_del(l);
                    free(e);
                    /* because entry matched is only one */
                    break;
                }
            }
        break;
    }
    free(ndle_tmp);

    return(0);
}

/*
 * debug neighbor discovery message
 */
void debug_ndmsg(int lev, struct ndmsg *ndm, struct rtattr *nda[], int ndm_len)
{
    char ifname[IFNAMSIZ] = "";

    /* debug ndmsg */
    if_indextoname_from_lists((unsigned)ndm->ndm_ifindex, ifname);

    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ ndmsg(%d) ]",
        NLMSG_ALIGN(sizeof(struct ndmsg)));
    rec_dbg(lev, "    ndm_family(%d): %d(%s)",
        sizeof(ndm->ndm_family), ndm->ndm_family, conv_af_type(ndm->ndm_family, 1));
    rec_dbg(lev, "    ndm_ifindex(%d): %d(%s)",
        sizeof(ndm->ndm_ifindex), ndm->ndm_ifindex, ifname);
    rec_dbg(lev, "    ndm_state(%d): %d(%s)",
        sizeof(ndm->ndm_state), ndm->ndm_state, conv_nud_state(ndm->ndm_state, 1));
    rec_dbg(lev, "    ndm_flags(%d): %d(%s)",
        sizeof(ndm->ndm_flags), ndm->ndm_flags, conv_ntf_flags(ndm->ndm_flags, 1));
    rec_dbg(lev, "    ndm_type(%d): %d(%s)",
        sizeof(ndm->ndm_type), ndm->ndm_type, conv_rtn_type(ndm->ndm_type, 1));

    /* debug neighbor discovery attributes */
    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ ndmsg attributes(%d) ]",
        NLMSG_ALIGN(ndm_len - NLMSG_ALIGN(sizeof(struct ndmsg))));

    if(nda[NDA_DST])
        debug_rta_af(lev+1, nda[NDA_DST],
            "NDA_DST", ndm->ndm_family);

    if(nda[NDA_LLADDR])
        debug_rta_arphrd(lev+1, nda[NDA_LLADDR],
            "NDA_LLADDR", ARPHRD_ETHER);

    if(nda[NDA_CACHEINFO])
        debug_nda_cacheinfo(lev+1, nda[NDA_CACHEINFO],
            "NDA_CACHEINFO");

    if(nda[NDA_PROBES])
        debug_rta_u32(lev+1, nda[NDA_PROBES],
            "NDA_PROBES", NULL);

    rec_dbg(lev, "");

    return;
}

/*
 * debug attribute NDA_CACHEINFO
 */
void debug_nda_cacheinfo(int lev, struct rtattr *nda, const char *name)
{
    struct nda_cacheinfo *ndac;

    if(debug_rta_len_chk(lev, nda, name, sizeof(*ndac)))
        return;

    ndac = (struct nda_cacheinfo *)RTA_DATA(nda);

    rec_dbg(lev, "%s(%hu):",
        name, RTA_ALIGN(nda->rta_len));
    rec_dbg(lev, "    [ nda_cacheinfo(%d) ]",
        sizeof(struct nda_cacheinfo));
    rec_dbg(lev, "        ndm_confirmed(%d): %u",
        sizeof(ndac->ndm_confirmed), ndac->ndm_confirmed);
    rec_dbg(lev, "        ndm_used(%d): %u",
        sizeof(ndac->ndm_used), ndac->ndm_used);
    rec_dbg(lev, "        ndm_updated(%d): %u",
        sizeof(ndac->ndm_updated), ndac->ndm_updated);
    rec_dbg(lev, "        ndm_refcnt(%d): %u",
        sizeof(ndac->ndm_refcnt), ndac->ndm_refcnt);

    return;
}

const char *conv_nud_state(int state, unsigned char debug)
{
#define _NUD_STATE(s) \
    if(state == NUD_##s) \
        return(#s);
    _NUD_STATE(INCOMPLETE);
    _NUD_STATE(REACHABLE);
    _NUD_STATE(STALE);
    _NUD_STATE(DELAY);
    _NUD_STATE(PROBE);
    _NUD_STATE(FAILED);
    _NUD_STATE(NOARP);
    _NUD_STATE(PERMANENT);
#undef _NUD_STATE
    return("UNKNOWN");
}

const char *conv_ntf_flags(int flags, unsigned char debug)
{
    static char list[MAX_STR_SIZE];
    unsigned len = sizeof(list);

    if(!flags) {
        strncpy(list, "NONE", len);
        return((const char *)list);
    }
#define _NTF_FLAGS(f) \
    if((flags & NTF_##f) && (len - strlen(list) - 1 > 0)) \
        (flags &= ~NTF_##f) ? \
            strncat(list, #f ",", len - strlen(list) - 1) : \
            strncat(list, #f, len - strlen(list) - 1);
#ifdef NTF_USE
    _NTF_FLAGS(USE);
#endif
    _NTF_FLAGS(PROXY);
    _NTF_FLAGS(ROUTER);
#undef _NTF_FLAGS
    if(!strlen(list))
        strncpy(list, "UNKNOWN", len);

    return((const char *)list);
}
