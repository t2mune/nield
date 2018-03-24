/*
 * ifimsg.c - interface information message parser
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

#define HIST_MAX 64

/* top of interface list and history */
static struct list_head lhead = {&lhead, &lhead};
static struct list_head hhead = {&hhead, &hhead};

/*
 * search an entry in an interface list
 */
static inline struct iflist_entry *search_iflist(int index)
{
    struct list_head *l;

    list_for_each(l, &lhead) {
        struct iflist_entry *e;

        e = list_entry(l, struct iflist_entry, list);
        if(e->index == index)
            return(e);
    }

    return(NULL);
}

/*
 * add an entry into an interface list
 */ 
static inline void add_iflist_entry(struct list_head *l)
{
    list_init(l);
    list_add(l, &lhead);

    return;
}

/*
 * [not in use]
 * delete an entry in an interface list
 */ 
static inline void del_iflist_entry(int index)
{
    struct list_head *l, *n;

    list_for_each_safe(l, n, &lhead) {
        struct iflist_entry *e;

        e = list_entry(l, struct iflist_entry, list);
        if(e->index == index) {
            list_del(l);
            free(e);
        }
    }

    return;
}

/*
 * move an entry in an interface list to an interface history
 */
static inline void move_iflist_entry(int index)
{
    struct list_head *l, *n;

    list_for_each_safe(l, n, &lhead) {
        struct iflist_entry *e;

        e = list_entry(l, struct iflist_entry, list);
        if(e->index == index) {
            list_move(l, &hhead);
            break;
        }
    }

    return;
}

/*
 * delete an old entry in an interface history
 */
static inline void del_ifhist_entry(void)
{
    struct list_head *l, *n;
    int i = 0;

    list_for_each_safe(l, n, &hhead) {
        struct iflist_entry *e;

        if(++i > HIST_MAX) {
            e = list_entry(l, struct iflist_entry, list);
            list_del(l);
            free(e);
            break;
        }
    }

    return;
}

/*
 * search an entry in an interface history
 */ 
static inline struct iflist_entry *search_ifhist(int index)
{
    struct list_head *l;

    list_for_each(l, &hhead) {
        struct iflist_entry *e;

        e = list_entry(l, struct iflist_entry, list);
        if(e->index == index)
            return(e);
    }

    return(NULL);
}

/*
 * conv an interface index to name in lists
 */
char *if_indextoname_from_lists(int index, char *name)
{
    /* from kernel */
    if(if_indextoname(index, name))
        return(name);

    /* from interface list */
    if(if_indextoname_from_iflist(index, name))
        return(name);

    /* from interface history */
    if(if_indextoname_from_ifhist(index, name))
        snprintf(name, IFNAMSIZ, "(unknown %d)", index);

    return(name);
}

/*
 * conv an interface index to name in an interface list
 */
char *if_indextoname_from_iflist(int index, char *name)
{
    struct iflist_entry *e = search_iflist(index);

    if(!e)
        return(NULL);

    strncpy(name, e->name, sizeof(e->name));

    return(name);
}

/*
 * conv an interface index to name in an inetrface history
 */ 
char *if_indextoname_from_ifhist(int index, char *name)
{
    struct iflist_entry *e = search_ifhist(index);

    if(!e)
        return(NULL);

    strncpy(name, e->name, sizeof(e->name));

    return(name);
}

/*
 * get an interface type in an interface list
 */ 
unsigned short get_type_from_iflist(int index)
{
    struct iflist_entry *e = search_iflist(index);

    if(!e)
        return(0);

    return(e->type);
}

/*
 * get an interface type in an interface history
 */
unsigned short get_type_from_ifhist(int index)
{
    struct iflist_entry *e = search_ifhist(index);

    if(!e)
        return(0);

    return(e->type);
}

/*
 * print an interface list
 */ 
void print_iflist(int num)
{
    struct list_head *head = NULL;
    struct list_head *l;
    FILE *iflist;
    char fname[MAX_STR_SIZE] = "";
    char title[MAX_STR_SIZE] = "";

    switch(num) {
        case 1:
            head = &lhead;
            strncpy(fname, IFLIST_FILE, sizeof(fname));
            strncpy(title, "interface list", sizeof(fname));
            break;
        case 2:
            head = &hhead;
            strncpy(fname, IFHIST_FILE, sizeof(fname));
            strncpy(title, "interface history", sizeof(fname));
            break;
        default:
            return;
    }
    iflist = fopen(fname, "w");
    if(iflist == NULL) {
        rec_log("error: %s: can't open iflist file(%s)", __func__, fname);
        return;
    }
    fprintf(iflist, "\n");
    fprintf(iflist, "*********************************************************************\n");
    fprintf(iflist, "[ %s ]\n", title);

    list_for_each(l, head) {
        struct iflist_entry *e;

        e = list_entry(l, struct iflist_entry, list);

        fprintf(iflist, "%s[%d]: address %s\n",
            e->name, e->index, e->addr);
        fprintf(iflist, "%s[%d]: broadcast %s\n",
            e->name, e->index, e->brd);
        fprintf(iflist, "%s[%d]: flags %s\n",
            e->name, e->index, conv_iff_flags(e->flags, 1));
        fprintf(iflist, "%s[%d]: type %s\n",
            e->name, e->index, conv_arphrd_type(e->type, 1));
        fprintf(iflist, "%s[%d]: vlan %hu\n",
            e->name, e->index, e->vid);
        fprintf(iflist, "%s[%d]: mtu %hu\n",
            e->name, e->index, e->mtu);
        fprintf(iflist, "%s[%d]: kind %s\n",
            e->name, e->index, strlen(e->kind) ? e->kind : "no");
        fprintf(iflist, "%s[%d]: master %s[%d]\n",
            e->name, e->index,
            strlen(e->name_master) ? e->name_master : "none" , e->index_master);
        fprintf(iflist, "%s[%d]: bridge-attached %s\n",
            e->name, e->index, e->br_attached ? "yes" : "no");
#if HAVE_DECL_IFLA_BRPORT_UNSPEC
        fprintf(iflist, "%s[%d]: bridge-port-state %s\n",
            e->name, e->index, conv_br_state(e->br_state, 0));
#endif
    }

    fclose(iflist);

    return;
}

/*
 * create an interface list
 */ 
int create_iflist(struct msghdr *msg)
{
    struct nlmsghdr *nlh;
    int nlh_len;
    struct ifinfomsg *ifim;
    int ifim_len;
    struct rtattr *ifla[__IFLA_MAX];
    struct iflist_entry *ifle;
    int log_opts = get_log_opts();

    /* get netlink message header */
    nlh = msg->msg_iov->iov_base;
    nlh_len = msg->msg_iov->iov_len;

    /* parse netlink message header */
    for( ; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
        /* whether netlink message header ends or not */
        if(nlh->nlmsg_type == NLMSG_DONE)
            return(1);

        /* debug nlmsghdr */
        if(log_opts & L_DEBUG)
            debug_nlmsg(0, nlh);

        /* get ifinfomsg */
        ifim_len = NLMSG_PAYLOAD(nlh, 0);
        if(ifim_len < sizeof(*ifim)) {
            rec_log("error: %s: ifinfomsg: length too short", __func__);
            continue;
        }
        ifim = (struct ifinfomsg *)NLMSG_DATA(nlh);

        /* parse interface infomation attributes */
        parse_ifinfo(ifla, nlh);

        /* debug ifinfomsg */
        if(log_opts & L_DEBUG)
            debug_ifimsg(0, ifim, ifla, ifim_len);

        /* check bridge interface */
        if(ifim->ifi_family == PF_BRIDGE) {
            ifle = search_iflist(ifim->ifi_index);
            if(ifle)
                ifle->br_attached = 1;
        }

        /* check protocol family(PF_UNSPEC only) */
        if(ifim->ifi_family != PF_UNSPEC)
            continue;

        /* create interface list */
        ifle = (struct iflist_entry *)malloc(sizeof(struct iflist_entry));
        if(ifle == NULL) {
            rec_log("error: %s: malloc(): failed", __func__);
            return(-1);
        }
        memset(ifle, 0, sizeof(struct iflist_entry));
        list_init(&(ifle->list));

        ifle->index = ifim->ifi_index;
        ifle->flags = ifim->ifi_flags;
        ifle->type = ifim->ifi_type;
        ifle->br_state = 255;

        /* get interface name */
        if(ifla[IFLA_IFNAME])
            if(parse_ifla_ifname(NULL, NULL, ifla[IFLA_IFNAME], ifle)) {
                free(ifle);
                continue;
            }

        /* get interface address */
        if(ifla[IFLA_ADDRESS])
            if(parse_ifla_address(NULL, NULL, ifla[IFLA_ADDRESS], ifle)) {
                free(ifle);
                continue;
            }

        /* get broadcast address */
        if(ifla[IFLA_BROADCAST])
            if(parse_ifla_broadcast(NULL, NULL, ifla[IFLA_BROADCAST], ifle)) {
                free(ifle);
                continue;
            }

#if HAVE_DECL_IFLA_LINKINFO
        /* get interface information */
        if(ifla[IFLA_LINKINFO])
            if(parse_ifla_linkinfo(NULL, NULL, ifla[IFLA_LINKINFO], ifle)) {
                free(ifle);
                continue;
            }
#endif

        /* get interface MTU */
        if(ifla[IFLA_MTU])
            if(parse_ifla_mtu(NULL, NULL, ifla[IFLA_MTU], ifle)) {
                free(ifle);
                continue;
            }

        /* get master interface */
        if(ifla[IFLA_MASTER])
            if(parse_ifla_master(NULL, NULL, ifla[IFLA_MASTER], ifle)) {
                free(ifle);
                continue;
            }

        /* get interface protocol information */
        if(ifla[IFLA_PROTINFO])
            if(parse_ifla_protinfo(ifla[IFLA_PROTINFO], ifle, ifim->ifi_family)) {
                free(ifle);
                continue;
            }

        /* add interface list */
        list_add(&(ifle->list), &lhead);
    }

    return(0);
}

/*
 * parse interface information message
 */
int parse_ifimsg(struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifim;
    int ifim_len;
    struct rtattr *ifla[__IFLA_MAX];
    struct iflist_entry *ifle_tmp, *ifle;
    char msg[MAX_MSG_SIZE] = "";
    char *mp = msg;
    int log_opts = get_log_opts();

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get ifinfomsg */
    ifim_len = NLMSG_PAYLOAD(nlh, 0);
    if(ifim_len < sizeof(*ifim)) {
        rec_log("error: %s: ifinfomsg: length too short", __func__);
        return(1);
    }
    ifim = (struct ifinfomsg *)NLMSG_DATA(nlh);

    /* parse interface infomation message attributes */
    parse_ifinfo(ifla, nlh);

    /* debug ifinfomsg */
    if(log_opts & L_DEBUG)
        debug_ifimsg(0, ifim, ifla, ifim_len);

    /* create new interface list entry */
    ifle_tmp = malloc(sizeof(struct iflist_entry));
    if(!ifle_tmp) {
        rec_log("error: %s: malloc() failed", __func__);
        return(1);
    }
    memset(ifle_tmp, 0, sizeof(struct iflist_entry));
    list_init(&(ifle_tmp->list));

    ifle_tmp->index = ifim->ifi_index;
    ifle_tmp->flags = ifim->ifi_flags;
    ifle_tmp->type = ifim->ifi_type;
    ifle_tmp->br_state = 255;

    /* get interface name */
    if(ifla[IFLA_IFNAME])
        if(parse_ifla_ifname(msg, &mp, ifla[IFLA_IFNAME], ifle_tmp)) {
            free(ifle_tmp);
            return(1);
        }

    /* get physical interface */
    if(ifla[IFLA_LINK])
        if(parse_ifla_link(msg, &mp, ifla[IFLA_LINK], ifle_tmp)) {
            free(ifle_tmp);
            return(1);
        }

    /* get interface address */
    if(ifla[IFLA_ADDRESS])
        if(parse_ifla_address(msg, &mp, ifla[IFLA_ADDRESS], ifle_tmp)) {
            free(ifle_tmp);
            return(1);
        }

    /* get broadcast address */
    if(ifla[IFLA_BROADCAST])
        if(parse_ifla_broadcast(msg, &mp, ifla[IFLA_BROADCAST], ifle_tmp)) {
            free(ifle_tmp);
            return(1);
        }

    /* get interface MTU */
    if(ifla[IFLA_MTU])
        if(parse_ifla_mtu(msg, &mp, ifla[IFLA_MTU], ifle_tmp)) {
            free(ifle_tmp);
            return(1);
        }

#if HAVE_DECL_IFLA_LINKINFO
    /* get interface information */
    if(ifla[IFLA_LINKINFO])
        if(parse_ifla_linkinfo(msg, &mp, ifla[IFLA_LINKINFO], ifle_tmp)) {
            free(ifle_tmp);
            return(1);
        }
#endif

    /* get master interface */
    if(ifla[IFLA_MASTER])
        if(parse_ifla_master(msg, &mp, ifla[IFLA_MASTER], ifle_tmp)) {
            free(ifle_tmp);
            return(1);
        }

    /* get interface protocol information */
    if(ifla[IFLA_PROTINFO])
        if(parse_ifla_protinfo(ifla[IFLA_PROTINFO], ifle_tmp, ifim->ifi_family)) {
            free(ifle_tmp);
            return(1);
        }

    /* check RTM message(only RTM_NEWLINK or RTMDELLINK) */
    if((nlh->nlmsg_type != RTM_NEWLINK) && (nlh->nlmsg_type != RTM_DELLINK)) {
        rec_log("error: %s: unknown nlmsg_type: %d", __func__, nlh->nlmsg_type);
        free(ifle_tmp);
        return(0);
    }

    /* search interface list entry */
    ifle = search_iflist(ifle_tmp->index);

#if HAVE_DECL_IFLA_BRPORT_UNSPEC
    /* check protocol family(PF_BRIDGE only) & nlmsg_type */
    if(ifim->ifi_family == PF_BRIDGE)
        /* workaround: "ovs-vsctl add-br" command */
        if(ifle_tmp->index != ifle_tmp->index_master)
            if(nlh->nlmsg_type == RTM_NEWLINK)
                parse_rtm_newlink_bridge(ifle, ifle_tmp, ifla);
            else if(nlh->nlmsg_type == RTM_DELLINK)
                parse_rtm_dellink_bridge(ifle);
#endif

    /* check protocol family(PF_UNSPEC only) */
    if(ifim->ifi_family != PF_UNSPEC) {
        free(ifle_tmp);
        return(0);
    }

    /* check nlmsg_type */
    if(nlh->nlmsg_type == RTM_NEWLINK)
        parse_rtm_newlink(msg, ifle, ifle_tmp, ifla);
    else if(nlh->nlmsg_type == RTM_DELLINK)
        parse_rtm_dellink(msg, ifle, ifle_tmp);

    return(0);
}

/*
 * parse RTM_NEWLINK
 */
void parse_rtm_newlink(char *msg, struct iflist_entry *ifle,
    struct iflist_entry *ifle_tmp, struct rtattr *ifla[])
{
    if(ifle) {
        /* check bonding interface */
        if(!(ifle->flags & IFF_SLAVE) && (ifle_tmp->flags & IFF_SLAVE)) {
            rec_log("interface %s attached to bonding %s",
                ifle_tmp->name, ifle_tmp->name_master);
            strncpy(ifle->name_master, ifle_tmp->name_master, sizeof(ifle->name_master));
        } else if((ifle->flags & IFF_SLAVE) && !(ifle_tmp->flags & IFF_SLAVE)) {
            rec_log("interface %s detached from bonding %s",
                ifle_tmp->name, ifle->name_master);
            strncpy(ifle->name_master, "", sizeof(ifle->name_master));
        }

        /* check administrative status */
        if((ifle->flags & IFF_UP) && !(ifle_tmp->flags & IFF_UP))
            rec_log("interface %s state changed to disabled",
                ifle_tmp->name);
        else if(!(ifle->flags & IFF_UP) && (ifle_tmp->flags & IFF_UP))
            rec_log("interface %s state changed to enabled",
                ifle_tmp->name);

        /* check operational status */
        if((ifle->flags & IFF_RUNNING) && !(ifle_tmp->flags & IFF_RUNNING))
            rec_log("interface %s state changed to down",
                ifle_tmp->name);
        else if(!(ifle->flags & IFF_RUNNING) && (ifle_tmp->flags & IFF_RUNNING))
            rec_log("interface %s state changed to up",
                ifle_tmp->name);

        /* check promiscuous status */
        if((ifle->flags & IFF_PROMISC) && !(ifle_tmp->flags & IFF_PROMISC))
            rec_log("interface %s left promiscuous mode",
                ifle_tmp->name);
        else if(!(ifle->flags & IFF_PROMISC) && (ifle_tmp->flags & IFF_PROMISC))
            rec_log("interface %s entered promiscuous mode",
                ifle_tmp->name);

        ifle->flags = ifle_tmp->flags;

        /* check interface name */
        if(ifla[IFLA_IFNAME]) {
            if(strncmp(ifle->name, ifle_tmp->name, IFNAMSIZ)) {
                rec_log("interface name changed from %s to %s",
                    ifle->name, ifle_tmp->name);
                strncpy(ifle->name, ifle_tmp->name, IFNAMSIZ);
            }
        }

        /* check interface address */
        if(ifla[IFLA_ADDRESS]) {
            if(memcmp(ifle->addr, ifle_tmp->addr, sizeof(ifle->addr))) {
                switch(ifle_tmp->type) {
                    case ARPHRD_TUNNEL:
                    case ARPHRD_IPGRE:
                    case ARPHRD_SIT:
                    case ARPHRD_TUNNEL6:
#ifdef ARPHRD_IP6GRE
                    case ARPHRD_IP6GRE:
#endif
                        rec_log("interface %s local address changed from %s to %s",
                            ifle->name, ifle->addr, ifle_tmp->addr);
                        break;
                    default:
                        rec_log("interface %s link layer address changed from %s to %s",
                            ifle->name, ifle->addr, ifle_tmp->addr);
                }
                memcpy(ifle->addr, ifle_tmp->addr, sizeof(ifle->addr));
            }
        }

        /* check broadcast address */
        if(ifla[IFLA_BROADCAST]) {
            if(memcmp(ifle->brd, ifle_tmp->brd, sizeof(ifle->brd))) {
                switch(ifle_tmp->type) {
                    case ARPHRD_TUNNEL:
                    case ARPHRD_IPGRE:
                    case ARPHRD_SIT:
                    case ARPHRD_TUNNEL6:
#ifdef ARPHRD_IP6GRE
                    case ARPHRD_IP6GRE:
#endif
                        rec_log("interface %s remote address changed from %s to %s",
                            ifle->name, ifle->brd, ifle_tmp->brd);
                        break;
                }
                memcpy(ifle->brd, ifle_tmp->brd, sizeof(ifle->brd));
            }
        }

        ifle->type = ifle_tmp->type;

        /* check interface MTU */
        if(ifla[IFLA_MTU]) {
            if(ifle->mtu != ifle_tmp->mtu) {
                rec_log("interface %s mtu changed from %d to %d",
                    ifle->name, ifle->mtu, ifle_tmp->mtu);
                ifle->mtu = ifle_tmp->mtu;
            }
        } 

        /* check interface vlan id */
        if(ifle->vid != ifle_tmp->vid) {
            rec_log("interface %s vlan id changed from %hu to %hu",
                ifle->name, ifle->vid, ifle_tmp->vid);
            ifle->vid = ifle_tmp->vid;
        }

        /* check master interface */
        if(ifle->index_master != ifle_tmp->index_master) {
            ifle->index_master = ifle_tmp->index_master;
        }

        free(ifle_tmp);
    } else {
        /* add interface list entry*/
        add_iflist_entry(&(ifle_tmp->list));

        /* check interface state */
        char state[MAX_STR_SIZE] = "";

        /* check administrative state */
        (ifle_tmp->flags & IFF_UP) ?
            strcpy(state, "enabled,") : strcpy(state, "disabled,");

        /* check operational state */
        (ifle_tmp->flags & IFF_RUNNING) ?
            strcat(state, "linkup") : strcat(state, "linkdown");

        rec_log("interface added: %sstate=%s", msg, state);
    }

    return;
}

/*
 * parse RTM_DEL_LINK
 */
void parse_rtm_dellink(char *msg, struct iflist_entry *ifle, struct iflist_entry *ifle_tmp)
{
    /* move entry from interface list to interface history */
    move_iflist_entry(ifle_tmp->index);
    del_ifhist_entry();

    /* check interface state */
    char state[MAX_STR_SIZE] = "";

    /* check administrative state */
    (ifle_tmp->flags & IFF_UP) ?
        strcpy(state, "enabled,") : strcpy(state, "disabled,");

    /* check operational state */
    (ifle_tmp->flags & IFF_RUNNING) ?
        strcat(state, "linkup") : strcat(state, "linkdown");

    rec_log("interface deleted: %sstate=%s", msg, state);
    free(ifle_tmp);

    return;
}

/*
 * psrse attribute IFLA_IFNAME
 */
int parse_ifla_ifname(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle)
{
    if(!RTA_PAYLOAD(ifla)) {
        rec_log("error: %s: ifindex %d: no payload",
            __func__, ifle->index);
        return(1);
    } else if(RTA_PAYLOAD(ifla) > sizeof(ifle->name)) {
        rec_log("error: %s: ifindex %d: payload too long",
            __func__, ifle->index);
        return(1);
    }
    strncpy(ifle->name, RTA_DATA(ifla), sizeof(ifle->name));

    if(msg)
        *mp = add_log(msg, *mp, "name=%s ", ifle->name);

    return(0);
}

/*
 * parse attribute IFLA_LINK
 */
int parse_ifla_link(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle)
{
    int index;
    char name[IFNAMSIZ] = "";

    if(RTA_PAYLOAD(ifla) < sizeof(index)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }
    index = *(int *)RTA_DATA(ifla);
    if(index && ifle->index != index) {
        if_indextoname_from_lists(index, name);

        *mp = add_log(msg, *mp, "link=%s ", name);
    }

    return(0);
}

/*
 * parse attribute IFLA_ADDRESS
 */
int parse_ifla_address(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = arphrd_ntop(ifle->type, ifla, addr, sizeof(addr));
    if(res) {
        rec_log("error: %s: ifindex %d: %s",
            __func__, ifle->index,
            (res == 1) ? strerror(errno) : "payload too short");
        return(1);
    }
    memcpy(ifle->addr, addr, sizeof(addr));

    if(msg)
        switch(ifle->type) {
            case ARPHRD_TUNNEL:
            case ARPHRD_IPGRE:
            case ARPHRD_SIT:
            case ARPHRD_TUNNEL6:
#ifdef ARPHRD_IP6GRE
            case ARPHRD_IP6GRE:
#endif
                *mp = add_log(msg, *mp, "local=%s ", ifle->addr);
                break;
            default:
                *mp = add_log(msg, *mp, "mac=%s ", ifle->addr);
        }

    return(0);
}

/*
 * parse attribute IFLA_BROADCAST
 */
int parse_ifla_broadcast(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle)
{
    char brd[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = arphrd_ntop(ifle->type, ifla, brd, sizeof(brd));
    if(res) {
        rec_log("error: %s: ifindex %d: %s",
            __func__, ifle->index,
            (res == 1) ? strerror(errno) : "pyaload too short");
        return(1);
    }
    memcpy(ifle->brd, brd, sizeof(brd));

    if(msg)
        switch(ifle->type) {
            case ARPHRD_TUNNEL:
            case ARPHRD_IPGRE:
            case ARPHRD_SIT:
            case ARPHRD_TUNNEL6:
#ifdef ARPHRD_IP6GRE
            case ARPHRD_IP6GRE:
#endif
                *mp = add_log(msg, *mp, "remote=%s ", ifle->brd);
                break;
        }

    return(0);
}

/*
 * parse attribute IFLA_MTU
 */
int parse_ifla_mtu(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(ifla) < sizeof(ifle->mtu)) {
        rec_log("error: %s: ifindex %d: payload too short",
            __func__, ifle->index);
        return(1);
    }
    ifle->mtu = *(int *)RTA_DATA(ifla);

    if(msg)
        *mp = add_log(msg, *mp, "mtu=%d ", ifle->mtu);

    return(0);
}

#if HAVE_DECL_IFLA_LINKINFO
/*
 * parse attribute IFLA_LINKINFO
 */
int parse_ifla_linkinfo(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle)
{
    struct rtattr *info[__IFLA_INFO_MAX];

    parse_nested_rtattr(info, IFLA_INFO_MAX, ifla);

    if(info[IFLA_INFO_KIND])
        if(parse_ifla_info_kind(msg, mp, info[IFLA_INFO_KIND], ifle))
            return(1);

    if(info[IFLA_INFO_DATA])
        if(parse_ifla_info_data(msg, mp, info[IFLA_INFO_DATA], ifle))
            return(1);

    return(0);
}

/*
 * parse attribute IFLA_INFO_KIND
 */
int parse_ifla_info_kind(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle)
{
    if(!RTA_PAYLOAD(info)) {
        rec_log("error: %s: ifindex %d: no payload",
            __func__, ifle->index);
        return(1);
    } if(RTA_PAYLOAD(info) > sizeof(ifle->kind)) {
        rec_log("error: %s: ifindex %d: payload too long",
            __func__, ifle->index);
        return(1);
    }
    strncpy(ifle->kind, (char *)RTA_DATA(info), sizeof(ifle->kind));

    if(msg)
        *mp = add_log(msg, *mp, "kind=%s ", ifle->kind);

    return(0);
}

/*
 * parse attribute IFLA_INFO_DATA
 */
int parse_ifla_info_data(char *msg, char **mp, struct rtattr *info, struct iflist_entry *ifle)
{
#if HAVE_DECL_IFLA_VLAN_UNSPEC
    if(!strncmp(ifle->kind, "vlan", sizeof(ifle->kind)))
        parse_ifla_vlan(msg, mp, info, ifle);
#endif
#if HAVE_DECL_IFLA_GRE_UNSPEC
    if(!strncmp(ifle->kind, "gre", sizeof(ifle->kind)))
        parse_ifla_gre(msg, mp, info, ifle);

    if(!strncmp(ifle->kind, "gretap", sizeof(ifle->kind)))
        parse_ifla_gre(msg, mp, info, ifle);
#endif
#if HAVE_DECL_IFLA_MACVLAN_UNSPEC
    if(!strncmp(ifle->kind, "macvlan", sizeof(ifle->kind)))
        parse_ifla_macvlan(msg, mp, info, ifle);

    if(!strncmp(ifle->kind, "macvtap", sizeof(ifle->kind)))
        parse_ifla_macvlan(msg, mp, info, ifle);
#endif
#if HAVE_DECL_IFLA_VXLAN_UNSPEC
    if(!strncmp(ifle->kind, "vxlan", sizeof(ifle->kind)))
        parse_ifla_vxlan(msg, mp, info, ifle);
#endif
#if HAVE_DECL_IFLA_BOND_UNSPEC
    if(!strncmp(ifle->kind, "bond", sizeof(ifle->kind)))
        parse_ifla_bond(msg, mp, info, ifle);
#endif
    return(0);
}
#endif

/*
 * parse attribute IFLA_MASTER
 */
int parse_ifla_master(char *msg, char **mp, struct rtattr *ifla, struct iflist_entry *ifle)
{
    if(RTA_PAYLOAD(ifla) < sizeof(ifle->index_master)) {
        rec_log("error: %s: IFLA_MASTER(ifindex %d): payload too short",
            __func__, ifle->index);
        return(1);
    }
    ifle->index_master = *(int *)RTA_DATA(ifla);
    if_indextoname_from_lists(ifle->index_master, ifle->name_master);

    if(msg)
        *mp = add_log(msg, *mp, "master=%s ", ifle->name_master);

    return(0);
}

/*
 * parse attribute IFLA_PROTINFO
 */
int parse_ifla_protinfo(struct rtattr *ifla, struct iflist_entry *ifle, unsigned char family)
{
#if HAVE_DECL_IFLA_BRPORT_UNSPEC
    if(family == PF_BRIDGE) 
        parse_ifla_brport(ifla, ifle);
#endif

    return(0);
}

/*
 * debug interface information message
 */ 
void debug_ifimsg(int lev, struct ifinfomsg *ifim, struct rtattr *ifla[], int ifim_len)
{
    /* debug ifinfomsg */
    char ifname[IFNAMSIZ] = "";

    if_indextoname_from_lists(ifim->ifi_index, ifname);

    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ ifinfomsg(%d) ]",
        NLMSG_ALIGN(sizeof(struct ifinfomsg)));
    rec_dbg(lev, "    ifi_family(%d): %u(%s)",
        sizeof(ifim->ifi_family), ifim->ifi_family,
        conv_af_type(ifim->ifi_family, 1));
    rec_dbg(lev, "    __ifi_pad(%d): %u",
        sizeof(ifim->__ifi_pad), ifim->__ifi_pad);
    rec_dbg(lev, "    ifi_type(%d): %hu(%s)",
        sizeof(ifim->ifi_type), ifim->ifi_type,
        conv_arphrd_type(ifim->ifi_type, 1));
    rec_dbg(lev, "    ifi_index(%d): %d(%s)",
        sizeof(ifim->ifi_index), ifim->ifi_index, ifname);
    rec_dbg(lev, "    ifi_flags(%d): 0x%08x(%s)",
        sizeof(ifim->ifi_flags), ifim->ifi_flags,
        conv_iff_flags(ifim->ifi_flags, 1));
    rec_dbg(lev, "    ifi_change(%d): %u",
        sizeof(ifim->ifi_change), ifim->ifi_change);

    /* debug interface link attributes */
    rec_dbg(lev, "*********************************************************************");
    rec_dbg(lev, "[ ifinfomsg attributes(%d) ]",
        NLMSG_ALIGN(ifim_len - NLMSG_ALIGN(sizeof(struct ifinfomsg))));

    if(ifla[IFLA_ADDRESS])
        debug_rta_arphrd(lev+1, ifla[IFLA_ADDRESS],
            "IFLA_ADDRESS", ifim->ifi_type);

    if(ifla[IFLA_BROADCAST])
        debug_rta_arphrd(lev+1, ifla[IFLA_BROADCAST],
            "IFLA_BROADCAST", ifim->ifi_type);

    if(ifla[IFLA_IFNAME])
        debug_rta_str(lev+1, ifla[IFLA_IFNAME],
            "IFLA_IFNAME", NULL, IFNAMSIZ);

    if(ifla[IFLA_MTU])
        debug_rta_s32(lev+1, ifla[IFLA_MTU],
            "IFLA_MTU", NULL);

    if(ifla[IFLA_LINK])
        debug_rta_ifindex(lev+1, ifla[IFLA_LINK],
            "IFLA_LINK");

    if(ifla[IFLA_QDISC])
        debug_rta_str(lev+1, ifla[IFLA_QDISC],
            "IFLA_QDISC", NULL, IFNAMSIZ);

    if(ifla[IFLA_STATS])
        debug_ifla_stats(lev+1, ifla[IFLA_STATS],
            "IFLA_STATS");

    if(ifla[IFLA_COST])
        debug_rta_u32(lev+1, ifla[IFLA_COST],
            "IFLA_COST", NULL);

    if(ifla[IFLA_PRIORITY])
        debug_rta_u32(lev+1, ifla[IFLA_PRIORITY],
            "IFLA_PRIORITY", NULL);

    if(ifla[IFLA_MASTER])
        debug_rta_ifindex(lev+1, ifla[IFLA_MASTER],
            "IFLA_MASTER");

    if(ifla[IFLA_WIRELESS])
        debug_rta_ignore(lev+1, ifla[IFLA_WIRELESS],
            "IFLA_WIRELESS");

    if(ifla[IFLA_PROTINFO])
        debug_ifla_protinfo(lev+1, ifla[IFLA_PROTINFO],
            "IFLA_PROTINFO", ifim->ifi_family);

    if(ifla[IFLA_TXQLEN])
        debug_rta_u32(lev+1, ifla[IFLA_TXQLEN],
            "IFLA_TXQLEN", NULL);

    if(ifla[IFLA_MAP])
        debug_ifla_map(lev+1, ifla[IFLA_MAP],
            "IFLA_MAP");

    if(ifla[IFLA_WEIGHT])
        debug_rta_u32(lev+1, ifla[IFLA_WEIGHT],
            "IFLA_WEIGHT", NULL);

    if(ifla[IFLA_OPERSTATE])
        debug_rta_u8(lev+1, ifla[IFLA_OPERSTATE],
            "IFLA_OPERSTATE", conv_if_oper_state);

    if(ifla[IFLA_LINKMODE])
        debug_rta_u8(lev+1, ifla[IFLA_LINKMODE],
            "IFLA_LINKMODE", conv_if_link_mode);

#if HAVE_DECL_IFLA_LINKINFO
    if(ifla[IFLA_LINKINFO])
        debug_ifla_linkinfo(lev+1, ifla[IFLA_LINKINFO],
            "IFLA_LINKINFO", ifim);
#endif
#if HAVE_DECL_IFLA_NET_NS_PID
    if(ifla[IFLA_NET_NS_PID])
        debug_rta_u32(lev+1, ifla[IFLA_NET_NS_PID],
            "IFLA_NET_NS_PID", NULL);
#endif
#if HAVE_DECL_IFLA_IFALIAS
    if(ifla[IFLA_IFALIAS])
        debug_rta_str(lev+1, ifla[IFLA_IFALIAS],
            "IFLA_IFALIAS", NULL, IFNAMSIZ);
#endif
#if HAVE_DECL_IFLA_NUM_VF
    if(ifla[IFLA_NUM_VF])
        debug_rta_u32(lev+1, ifla[IFLA_NUM_VF],
            "IFLA_NUM_VF", NULL);
#endif
#if HAVE_DECL_IFLA_VFINFO_LIST
    if(ifla[IFLA_VFINFO_LIST])
        debug_rta_ignore(lev+1, ifla[IFLA_VFINFO_LIST],
            "IFLA_VFINFO_LIST");
#endif
#if HAVE_DECL_IFLA_STATS64
    if(ifla[IFLA_STATS64])
        debug_ifla_stats64(lev+1, ifla[IFLA_STATS64],
            "IFLA_STATS64");
#endif
#if HAVE_DECL_IFLA_VF_PORTS
    if(ifla[IFLA_VF_PORTS])
        debug_rta_ignore(lev+1, ifla[IFLA_VF_PORTS],
            "IFLA_VF_PORTS");
#endif
#if HAVE_DECL_IFLA_PORT_SELF
    if(ifla[IFLA_PORT_SELF])
        debug_rta_ignore(lev+1, ifla[IFLA_PORT_SELF],
            "IFLA_PORT_SELF");
#endif
#if HAVE_DECL_IFLA_AF_SPEC
    if(ifla[IFLA_AF_SPEC])
        debug_rta_ignore(lev+1, ifla[IFLA_AF_SPEC],
            "IFLA_AF_SPEC");
#endif
#if HAVE_DECL_IFLA_GROUP
    if(ifla[IFLA_GROUP])
        debug_rta_s32(lev+1, ifla[IFLA_GROUP],
            "IFLA_GROUP", NULL);
#endif
#if HAVE_DECL_IFLA_NET_NS_FD
    if(ifla[IFLA_NET_NS_FD])
        debug_rta_ignore(lev+1, ifla[IFLA_NET_NS_FD],
            "IFLA_NET_NS_FD");
#endif
#if HAVE_DECL_IFLA_EXT_MASK
    if(ifla[IFLA_EXT_MASK])
        debug_rta_ignore(lev+1, ifla[IFLA_EXT_MASK],
            "IFLA_EXT_MASK");
#endif
#if HAVE_DECL_IFLA_PROMISCUITY
    if(ifla[IFLA_PROMISCUITY])
        debug_rta_s32(lev+1, ifla[IFLA_PROMISCUITY],
            "IFLA_PROMISCUITY", NULL);
#endif
#if HAVE_DECL_IFLA_NUM_TX_QUEUES
    if(ifla[IFLA_NUM_TX_QUEUES])
        debug_rta_s32(lev+1, ifla[IFLA_NUM_TX_QUEUES],
            "IFLA_NUM_TX_QUEUES", NULL);
#endif
#if HAVE_DECL_IFLA_NUM_RX_QUEUES
    if(ifla[IFLA_NUM_RX_QUEUES])
        debug_rta_s32(lev+1, ifla[IFLA_NUM_RX_QUEUES],
            "IFLA_NUM_RX_QUEUES", NULL);
#endif
#if HAVE_DECL_IFLA_CARRIER
    if(ifla[IFLA_CARRIER])
        debug_rta_ignore(lev+1, ifla[IFLA_CARRIER],
            "IFLA_CARRIER");
#endif
#if HAVE_DECL_IFLA_PHYS_PORT_ID
    if(ifla[IFLA_PHYS_PORT_ID])
        debug_rta_ignore(lev+1, ifla[IFLA_PHYS_PORT_ID],
            "IFLA_PHYS_PORT_ID");
#endif

    rec_dbg(lev, "");

    return;
}

/*
 * debug attribute IFLA_STATS
 */ 
void debug_ifla_stats(int lev, struct rtattr *ifla, const char *name)
{
    struct rtnl_link_stats *stats;

    if(debug_rta_len_chk(lev, ifla, name, sizeof(*stats)))
        return;

    stats = (struct rtnl_link_stats *)RTA_DATA(ifla);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(ifla->rta_len));
    rec_dbg(lev, "    [ rtnl_link_stats(%d) ]", sizeof(*stats));
    rec_dbg(lev, "        rx_packets(%d): %u",
        sizeof(stats->rx_packets), stats->rx_packets);
    rec_dbg(lev, "        tx_packets(%d): %u",
        sizeof(stats->tx_packets), stats->tx_packets);
    rec_dbg(lev, "        rx_bytes(%d): %u",
        sizeof(stats->rx_bytes), stats->rx_bytes);
    rec_dbg(lev, "        tx_bytes(%d): %u",
        sizeof(stats->tx_bytes), stats->tx_bytes);
    rec_dbg(lev, "        rx_errors(%d): %u",
        sizeof(stats->rx_errors), stats->rx_errors);
    rec_dbg(lev, "        tx_errors(%d): %u",
        sizeof(stats->tx_errors), stats->tx_errors);
    rec_dbg(lev, "        rx_dropped(%d): %u",
        sizeof(stats->rx_dropped), stats->rx_dropped);
    rec_dbg(lev, "        tx_dropped(%d): %u",
        sizeof(stats->tx_dropped), stats->tx_dropped);
    rec_dbg(lev, "        multicast(%d): %u",
        sizeof(stats->multicast), stats->multicast);
    rec_dbg(lev, "        collisions(%d): %u",
        sizeof(stats->collisions), stats->collisions);
    rec_dbg(lev, "        rx_length_errors(%d): %u",
        sizeof(stats->rx_length_errors), stats->rx_length_errors);
    rec_dbg(lev, "        rx_over_errors(%d): %u",
        sizeof(stats->rx_over_errors), stats->rx_over_errors);
    rec_dbg(lev, "        rx_crc_errors(%d): %u",
        sizeof(stats->rx_crc_errors), stats->rx_crc_errors);
    rec_dbg(lev, "        rx_frame_errors(%d): %u",
        sizeof(stats->rx_frame_errors), stats->rx_frame_errors);
    rec_dbg(lev, "        rx_fifo_errors(%d): %u",
        sizeof(stats->rx_fifo_errors), stats->rx_fifo_errors);
    rec_dbg(lev, "        rx_missed_errors(%d): %u",
        sizeof(stats->rx_missed_errors), stats->rx_missed_errors);
    rec_dbg(lev, "        tx_aborted_errors(%d): %u",
        sizeof(stats->tx_aborted_errors), stats->tx_aborted_errors);
    rec_dbg(lev, "        tx_carrier_errors(%d): %u",
        sizeof(stats->tx_carrier_errors), stats->tx_carrier_errors);
    rec_dbg(lev, "        tx_fifo_errors(%d): %u",
        sizeof(stats->tx_fifo_errors), stats->tx_fifo_errors);
    rec_dbg(lev, "        tx_heartbeat_errors(%d): %u",
        sizeof(stats->tx_heartbeat_errors), stats->tx_heartbeat_errors);
    rec_dbg(lev, "        tx_window_errors(%d): %u",
        sizeof(stats->tx_window_errors), stats->tx_window_errors);
    rec_dbg(lev, "        rx_compressed(%d): %u",
        sizeof(stats->rx_compressed), stats->rx_compressed);
    rec_dbg(lev, "        tx_compressed(%d): %u",
        sizeof(stats->tx_compressed), stats->tx_compressed);

    return;
}

/*
 * debug attribute IFLA_PROTOINFO
 */ 
void debug_ifla_protinfo(int lev, struct rtattr *ifla,
    const char *name, unsigned char family)
{
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(ifla->rta_len));

#if HAVE_DECL_IFLA_BRPORT_UNSPEC
    if(family == PF_BRIDGE)
        debug_ifla_brport(lev, ifla);
#endif

    return;
}

/*
 * debug attribute IFLA_MAP
 */ 
void debug_ifla_map(int lev, struct rtattr *ifla, const char *name)
{
    struct rtnl_link_ifmap *map;

    if(debug_rta_len_chk(lev, ifla, name, sizeof(*map)))
        return;

    map = (struct rtnl_link_ifmap *)RTA_DATA(ifla);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(ifla->rta_len));
    rec_dbg(lev, "    [ rtnl_link_ifmap(%d) ]", sizeof(*map));
    rec_dbg(lev, "        mem_start(%d): 0x%016x",
        sizeof(map->mem_start), map->mem_start);
    rec_dbg(lev, "        mem_end(%d): 0x%016x",
        sizeof(map->mem_end), map->mem_end);
    rec_dbg(lev, "        base_addr(%d): 0x%016x",
        sizeof(map->base_addr), map->base_addr);
    rec_dbg(lev, "        irq(%d): %hu",
        sizeof(map->irq), map->irq);
    rec_dbg(lev, "        dma(%d): 0x%02x",
        sizeof(map->dma), map->dma);
    rec_dbg(lev, "        port(%d): 0x%02x",
        sizeof(map->port), map->port);

    return;
}

#if HAVE_DECL_IFLA_LINKINFO
/*
 * debug attribute IFLA_LINKINFO
 */
void debug_ifla_linkinfo(int lev, struct rtattr *ifla,
        const char *name, struct ifinfomsg *ifim)
{
    struct rtattr *info[__IFLA_INFO_MAX];
    char kind[MODULE_NAME_LEN] = "";

    parse_nested_rtattr(info, IFLA_INFO_MAX, ifla);

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(ifla->rta_len));

    if(info[IFLA_INFO_KIND])
        debug_rta_str(lev+1, info[IFLA_INFO_KIND],
            "IFLA_INFO_KIND", kind, sizeof(kind));

    if(info[IFLA_INFO_DATA])
        debug_ifla_info_data(lev+1, info[IFLA_INFO_DATA],
            "IFLA_INFO_DATA", ifim, kind, sizeof(kind));

    if(info[IFLA_INFO_XSTATS])
        debug_rta_ignore(lev+1, info[IFLA_INFO_XSTATS],
            "IFLA_INFO_XSTATS");

#if HAVE_DECL_IFLA_INFO_SLAVE_KIND
    if(info[IFLA_INFO_SLAVE_KIND])
        debug_rta_str(lev+1, info[IFLA_INFO_SLAVE_KIND],
            "IFLA_INFO_SLAVE_KIND", kind, sizeof(kind));

    if(info[IFLA_INFO_SLAVE_DATA])
        debug_ifla_info_slave_data(lev+1, info[IFLA_INFO_SLAVE_DATA],
            "IFLA_INFO_SLAVE_DATA", ifim, kind, sizeof(kind));
#endif

    return;
}

/*
 * debug attribute IFLA_INFO_DATA
 */
void debug_ifla_info_data(int lev, struct rtattr *info,
    const char *name, struct ifinfomsg *ifim, char *kind, int len)
{
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(info->rta_len));

#if HAVE_DECL_IFLA_VLAN_UNSPEC
    if(!strncmp(kind, "vlan", len)) {
        debug_ifla_vlan(lev, info);
        return;
    }
#endif
#if HAVE_DECL_IFLA_GRE_UNSPEC
    if(!strncmp(kind, "gre", len)) {
        debug_ifla_gre(lev, ifim, info);
        return;
    }

    if(!strncmp(kind, "gretap", len)) {
        debug_ifla_gre(lev, ifim, info);
        return;
    }
#endif
#if HAVE_DECL_IFLA_MACVLAN_UNSPEC
    if(!strncmp(kind, "macvlan", len)) {
        debug_ifla_macvlan(lev, info);
        return;
    }

    if(!strncmp(kind, "macvtap", len)) {
        debug_ifla_macvlan(lev, info);
        return;
    }
#endif
#if HAVE_DECL_IFLA_VXLAN_UNSPEC
    if(!strncmp(kind, "vxlan", len)) { 
        debug_ifla_vxlan(lev, info);
        return;
    }
#endif
#if HAVE_DECL_IFLA_BOND_UNSPEC
    if(!strncmp(kind, "bond", len)) { 
        debug_ifla_bond(lev, info);
        return;
    }
#endif

    rec_dbg(lev, "%s(%hu): -- ignored --",
        name, RTA_ALIGN(info->rta_len));

    return;
}
#endif

#if HAVE_DECL_IFLA_INFO_SLAVE_KIND
/*
 * debug attribute IFLA_INFO_SLAVE_DATA
 */
void debug_ifla_info_slave_data(int lev, struct rtattr *info,
    const char *name, struct ifinfomsg *ifim, char *kind, int len)
{
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(info->rta_len));

#if HAVE_DECL_IFLA_BOND_MIIMON
    if(!strncmp(kind, "bond", len)) {
        debug_ifla_bond_slave(lev, info);
        return;
    }
#endif

    rec_dbg(lev, "%s(%hu): -- ignored --",
        name, RTA_ALIGN(info->rta_len));

    return;
}
#endif

#if HAVE_DECL_IFLA_STATS64
/*
 * debug attribute IFLA_STATS64
 */
void debug_ifla_stats64(int lev, struct rtattr *ifla, const char *name)
{
    struct rtnl_link_stats64 *stats;

    if(debug_rta_len_chk(lev, ifla, name, sizeof(*stats)))
        return;

    stats = (struct rtnl_link_stats64 *)RTA_DATA(ifla);
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(ifla->rta_len));
    rec_dbg(lev, "    [ rtnl_link_stats64(%d) ]", sizeof(*stats));
    rec_dbg(lev, "        rx_packets(%d): %llu",
        sizeof(stats->rx_packets), stats->rx_packets);
    rec_dbg(lev, "        tx_packets(%d): %llu",
        sizeof(stats->tx_packets), stats->tx_packets);
    rec_dbg(lev, "        rx_bytes(%d): %llu",
        sizeof(stats->rx_bytes), stats->rx_bytes);
    rec_dbg(lev, "        tx_bytes(%d): %llu",
        sizeof(stats->tx_bytes), stats->tx_bytes);
    rec_dbg(lev, "        rx_errors(%d): %llu",
        sizeof(stats->rx_errors), stats->rx_errors);
    rec_dbg(lev, "        tx_errors(%d): %llu",
        sizeof(stats->tx_errors), stats->tx_errors);
    rec_dbg(lev, "        rx_dropped(%d): %llu",
        sizeof(stats->rx_dropped), stats->rx_dropped);
    rec_dbg(lev, "        tx_dropped(%d): %llu",
        sizeof(stats->tx_dropped), stats->tx_dropped);
    rec_dbg(lev, "        multicast(%d): %llu",
        sizeof(stats->multicast), stats->multicast);
    rec_dbg(lev, "        collisions(%d): %llu",
        sizeof(stats->collisions), stats->collisions);
    rec_dbg(lev, "        rx_length_errors(%d): %llu",
        sizeof(stats->rx_length_errors), stats->rx_length_errors);
    rec_dbg(lev, "        rx_over_errors(%d): %llu",
        sizeof(stats->rx_over_errors), stats->rx_over_errors);
    rec_dbg(lev, "        rx_crc_errors(%d): %llu",
        sizeof(stats->rx_crc_errors), stats->rx_crc_errors);
    rec_dbg(lev, "        rx_frame_errors(%d): %llu",
        sizeof(stats->rx_frame_errors), stats->rx_frame_errors);
    rec_dbg(lev, "        rx_fifo_errors(%d): %llu",
        sizeof(stats->rx_fifo_errors), stats->rx_fifo_errors);
    rec_dbg(lev, "        rx_missed_errors(%d): %llu",
        sizeof(stats->rx_missed_errors), stats->rx_missed_errors);
    rec_dbg(lev, "        tx_aborted_errors(%d): %llu",
        sizeof(stats->tx_aborted_errors), stats->tx_aborted_errors);
    rec_dbg(lev, "        tx_carrier_errors(%d): %llu",
        sizeof(stats->tx_carrier_errors), stats->tx_carrier_errors);
    rec_dbg(lev, "        tx_fifo_errors(%d): %llu",
        sizeof(stats->tx_fifo_errors), stats->tx_fifo_errors);
    rec_dbg(lev, "        tx_heartbeat_errors(%d): %llu",
        sizeof(stats->tx_heartbeat_errors), stats->tx_heartbeat_errors);
    rec_dbg(lev, "        tx_window_errors(%d): %llu",
        sizeof(stats->tx_window_errors), stats->tx_window_errors);
    rec_dbg(lev, "        rx_compressed(%d): %llu",
        sizeof(stats->rx_compressed), stats->rx_compressed);
    rec_dbg(lev, "        tx_compressed(%d): %llu",
        sizeof(stats->tx_compressed), stats->tx_compressed);

    return;
}
#endif

/*
 * convert address family from number to string
 */
const char *conv_af_type(unsigned char family, unsigned char debug)
{
#define _AF_TYPE(s) \
    if(family == AF_##s) \
        return #s;
    _AF_TYPE(UNSPEC);
    _AF_TYPE(LOCAL);
    _AF_TYPE(UNIX);
    _AF_TYPE(FILE);
    _AF_TYPE(INET);
    _AF_TYPE(AX25);
    _AF_TYPE(IPX);
    _AF_TYPE(APPLETALK);
    _AF_TYPE(NETROM);
    _AF_TYPE(BRIDGE);
    _AF_TYPE(ATMPVC);
    _AF_TYPE(X25);
    _AF_TYPE(INET6);
    _AF_TYPE(ROSE);
    _AF_TYPE(DECnet);
    _AF_TYPE(NETBEUI);
    _AF_TYPE(SECURITY);
    _AF_TYPE(KEY);
    _AF_TYPE(NETLINK);
    _AF_TYPE(ROUTE);
    _AF_TYPE(PACKET);
    _AF_TYPE(ASH);
    _AF_TYPE(ECONET);
    _AF_TYPE(ATMSVC);
#ifdef AF_RDS
    _AF_TYPE(RDS);
#endif
    _AF_TYPE(SNA);
    _AF_TYPE(IRDA);
    _AF_TYPE(PPPOX);
    _AF_TYPE(WANPIPE);
#ifdef AF_LLC
    _AF_TYPE(LLC);
#endif
#ifdef AF_CAN
    _AF_TYPE(CAN);
#endif
#ifdef AF_TIPC
    _AF_TYPE(TIPC);
#endif
    _AF_TYPE(BLUETOOTH);
#ifdef AF_IUCV
    _AF_TYPE(IUCV);
#endif
#ifdef AF_RXRPC
    _AF_TYPE(RXRPC);
#endif
#ifdef AF_ISDN
    _AF_TYPE(ISDN);
#endif
#ifdef AF_PHONET
    _AF_TYPE(PHONET);
#endif
#ifdef AF_IEEE802154
    _AF_TYPE(IEEE802154);
#endif
#ifdef AF_CAIF
    _AF_TYPE(CAIF);
#endif
#ifdef AF_ALG
    _AF_TYPE(ALG);
#endif
    _AF_TYPE(MAX);
#undef _AF_TYPE
    return("UNKNOWN");
}

/*
 * convert interafce type from number to string
 */ 
const char *conv_arphrd_type(unsigned short type, unsigned char debug)
{
#define _ARPHRD_TYPE(s) \
    if(type == ARPHRD_##s) \
        return(#s);
    _ARPHRD_TYPE(NETROM);
    _ARPHRD_TYPE(ETHER);
    _ARPHRD_TYPE(EETHER);
    _ARPHRD_TYPE(AX25);
    _ARPHRD_TYPE(PRONET);
    _ARPHRD_TYPE(CHAOS);
    _ARPHRD_TYPE(IEEE802);
    _ARPHRD_TYPE(ARCNET);
    _ARPHRD_TYPE(APPLETLK);
    _ARPHRD_TYPE(DLCI);
    _ARPHRD_TYPE(ATM);
    _ARPHRD_TYPE(METRICOM);
    _ARPHRD_TYPE(IEEE1394);
    _ARPHRD_TYPE(EUI64);
    _ARPHRD_TYPE(INFINIBAND);
    _ARPHRD_TYPE(SLIP);
    _ARPHRD_TYPE(CSLIP);
    _ARPHRD_TYPE(SLIP6);
    _ARPHRD_TYPE(CSLIP6);
    _ARPHRD_TYPE(RSRVD);
    _ARPHRD_TYPE(ADAPT);
    _ARPHRD_TYPE(ROSE);
    _ARPHRD_TYPE(X25);
    _ARPHRD_TYPE(HWX25);
#ifdef ARPHRD_CAN
    _ARPHRD_TYPE(CAN);
#endif
    _ARPHRD_TYPE(PPP);
    _ARPHRD_TYPE(CISCO);
    _ARPHRD_TYPE(HDLC);
    _ARPHRD_TYPE(LAPB);
    _ARPHRD_TYPE(DDCMP);
    _ARPHRD_TYPE(RAWHDLC);
    _ARPHRD_TYPE(TUNNEL);
    _ARPHRD_TYPE(TUNNEL6);
    _ARPHRD_TYPE(FRAD);
    _ARPHRD_TYPE(SKIP);
    _ARPHRD_TYPE(LOOPBACK);
    _ARPHRD_TYPE(LOCALTLK);
    _ARPHRD_TYPE(FDDI);
    _ARPHRD_TYPE(BIF);
    _ARPHRD_TYPE(SIT);
    _ARPHRD_TYPE(IPDDP);
    _ARPHRD_TYPE(IPGRE);
    _ARPHRD_TYPE(PIMREG);
    _ARPHRD_TYPE(HIPPI);
    _ARPHRD_TYPE(ASH);
    _ARPHRD_TYPE(ECONET);
    _ARPHRD_TYPE(IRDA);
    _ARPHRD_TYPE(FCPP);
    _ARPHRD_TYPE(FCAL);
    _ARPHRD_TYPE(FCPL);
    _ARPHRD_TYPE(FCFABRIC);
    _ARPHRD_TYPE(IEEE802_TR);
    _ARPHRD_TYPE(IEEE80211);
    _ARPHRD_TYPE(IEEE80211_PRISM);
    _ARPHRD_TYPE(IEEE80211_RADIOTAP);
#ifdef ARPHRD_IEEE802154
    _ARPHRD_TYPE(IEEE802154);
#endif
#ifdef ARPHRD_PHONET
    _ARPHRD_TYPE(PHONET);
#endif
#ifdef ARPHRD_PHONET_PIPE
    _ARPHRD_TYPE(PHONET_PIPE);
#endif
#ifdef ARPHRD_CAIF
    _ARPHRD_TYPE(CAIF);
#endif
#ifdef ARPHRD_IP6GRE
    _ARPHRD_TYPE(IP6GRE);
#endif
#undef _ARPHRD_TYPE
    return("UNKNOWN");
}

/*
 * convert interface flags from number to string
 */
const char *conv_iff_flags(unsigned flags, unsigned char debug)
{
    static char list[MAX_STR_SIZE];
    unsigned len = sizeof(list);

    strncpy(list, "", sizeof(list));
    if(!flags) {
        strncpy(list, "NONE", len);
        return((const char *)list);
    }
#define _IFF_FLAGS(s) \
    if((flags & IFF_##s) && (len - strlen(list) -1 > 0)) \
        (flags &= ~IFF_##s) ? \
            strncat(list, #s ",", len - strlen(list) - 1) : \
            strncat(list, #s, len - strlen(list) - 1);
    _IFF_FLAGS(UP);
    _IFF_FLAGS(BROADCAST);
    _IFF_FLAGS(DEBUG);
    _IFF_FLAGS(LOOPBACK);
    _IFF_FLAGS(POINTOPOINT);
    _IFF_FLAGS(NOTRAILERS);
    _IFF_FLAGS(RUNNING);
    _IFF_FLAGS(NOARP);
    _IFF_FLAGS(PROMISC);
    _IFF_FLAGS(ALLMULTI);
    _IFF_FLAGS(MASTER);
    _IFF_FLAGS(SLAVE);
    _IFF_FLAGS(MULTICAST);
    _IFF_FLAGS(PORTSEL);
    _IFF_FLAGS(AUTOMEDIA);
    _IFF_FLAGS(DYNAMIC);
    _IFF_FLAGS(LOWER_UP);
    _IFF_FLAGS(DORMANT);
#ifdef IFF_ECHO
    _IFF_FLAGS(ECHO);
#endif
#undef _IFF_FLAGS
    if(!strlen(list))
        strncpy(list, "UNKNOWN", len);

    return((const char *)list);
}

/*
 * convert interafce operational state from number to string
 */
const char *conv_if_oper_state(unsigned char state, unsigned char debug)
{
#define _IF_OPER_STATE(s) \
    if(state == IF_OPER_##s) \
        return(#s);
    _IF_OPER_STATE(UNKNOWN);
    _IF_OPER_STATE(NOTPRESENT);
    _IF_OPER_STATE(DOWN);
    _IF_OPER_STATE(LOWERLAYERDOWN);
    _IF_OPER_STATE(TESTING);
    _IF_OPER_STATE(DORMANT);
    _IF_OPER_STATE(UP);
#undef _IF_OPER_STATE
    return("UNKNOWN");
}

/*
 * convert interafce link mode from number to string
 */
const char *conv_if_link_mode(unsigned char mode, unsigned char debug)
{
#define _IFLA_LINKMODE(s) \
    if(mode == IF_LINK_MODE_##s) \
        return(#s);
    _IFLA_LINKMODE(DEFAULT);
    _IFLA_LINKMODE(DORMANT);
#undef _IFLA_LINKMODE
    return("UNKNOWN");
}
