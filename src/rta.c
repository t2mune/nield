/*
 * rta.c - interface information message parser
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
 * check attribute payload length for debug
 */
int debug_rta_len_chk(int lev, struct rtattr *rta, const char *name, size_t len)
{
    if(RTA_PAYLOAD(rta) < len) {
        rec_dbg(lev, "%s(%hu): -- payload too short --",
            name, RTA_ALIGN(rta->rta_len));
        return(1);
    }

    return(0);
}

/*
 * ignore attribute
 */
void debug_rta_ignore(int lev, struct rtattr *rta, const char *name)
{
        rec_dbg(lev, "%s(%hu): -- ignored --", name, RTA_ALIGN(rta->rta_len));
}

/*
 *  no value attribute
 */
void debug_rta_none(int lev, struct rtattr *rta, const char *name)
{
        rec_dbg(lev, "%s(%hu): -- none --", name, RTA_ALIGN(rta->rta_len));
}
/*
 * debug unsigned char attribute
 */
void debug_rta_u8(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned char num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned char)))
        return;

    unsigned char data = *(unsigned char *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): %u(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): %u", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug unsigned char attribute
 */
void debug_rta_u8x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned char num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned char)))
        return;

    unsigned char data = *(unsigned char *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): %02x(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): %02x", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug unsigned short attribute
 */
void debug_rta_u16(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned short)))
        return;

    unsigned short data = *(unsigned short *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): %hu(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): %hu", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug unsigned short attribute
 */
void debug_rta_u16x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned short)))
        return;

    unsigned short data = *(unsigned short *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): 0x%04x(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): 0x%04x", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug unsigned short attribute
 */
void debug_rta_n16(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned short)))
        return;

    unsigned short data = ntohs(*(unsigned short *)RTA_DATA(rta));

    if(conv)
        rec_dbg(lev, "%s(%hu): %hu(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): %hu", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug unsigned short attribute
 */
void debug_rta_n16x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned short num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned short)))
        return;

    unsigned short data = ntohs(*(unsigned short *)RTA_DATA(rta));

    if(conv)
        rec_dbg(lev, "%s(%hu): 0x%04x(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): 0x%04x", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug unsigned attribute
 */
void debug_rta_u32(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned)))
        return;

    unsigned data = *(unsigned *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): %u(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): %u", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug unsigned attribute
 */
void debug_rta_u32x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(unsigned num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned)))
        return;

    unsigned data = *(unsigned *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): 0x%08u(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): 0x%08u", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug int attribute
 */
void debug_rta_s32(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(int num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(int)))
        return;

    int data = *(int *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): %d(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): %d", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug int attribute
 */
void debug_rta_s32x(int lev, struct rtattr *rta, const char *name,
    const char *(*conv)(int num, unsigned char debug))
{
    if(debug_rta_len_chk(lev, rta, name, sizeof(int)))
        return;

    int data = *(int *)RTA_DATA(rta);

    if(conv)
        rec_dbg(lev, "%s(%hu): 0x%08x(%s)", name, RTA_ALIGN(rta->rta_len), data,
            conv(data, 1));
    else
        rec_dbg(lev, "%s(%hu): 0x%08x", name, RTA_ALIGN(rta->rta_len), data);

    return;
}

/*
 * debug string attribute
 */ 
void debug_rta_str(int lev, struct rtattr *rta, const char *name,
    char *str, unsigned len)
{
    if(RTA_PAYLOAD(rta) > len) {
        rec_dbg(lev, "%s(%hu): -- payload too long --",
            name, RTA_ALIGN(rta->rta_len));
        return;
    }

    char *p = (char *)malloc(len);
    if(p == NULL)
        return;
    memset(p, 0, len);

    /* always p[len] == NULL */
    strncpy(p, (char *)RTA_DATA(rta), len - 1);
    rec_dbg(lev, "%s(%hu): %s", name, RTA_ALIGN(rta->rta_len), p);

    if(str)
        strncpy(str, p, len);

    free(p);

    return;
}

/*
 * debug interface index attribute
 */ 
void debug_rta_ifindex(int lev, struct rtattr *rta, const char *name)
{
    unsigned ifindex;
    char ifname[IFNAMSIZ] = "";

    if(debug_rta_len_chk(lev, rta, name, sizeof(unsigned)))
        return;
    ifindex = *(unsigned *)RTA_DATA(rta);
    if_indextoname_from_lists(ifindex, ifname);
    rec_dbg(lev, "%s(%hu): %u(%s)",
        name, RTA_ALIGN(rta->rta_len), ifindex, ifname);

    return;
}

/*
 * debug ARPHRD_* address attribute
 */ 
void debug_rta_arphrd(int lev, struct rtattr *rta, const char *name,
    unsigned short type)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = arphrd_ntop(type, rta, addr, sizeof(addr));
    if(res) {
        rec_dbg(lev, "%s(%hu): -- %s --",
            name, RTA_ALIGN(rta->rta_len),
            (res == 1) ? strerror(errno) : "payload too short");
        return;
    }
    rec_dbg(lev, "%s(%hu): %s", name, RTA_ALIGN(rta->rta_len), addr);

    return;
}

/*
 * convert interface address from binary to text
 */ 
int arphrd_ntop(unsigned short type, struct rtattr *ifla, char *dst, int dstlen)
{
    unsigned char *src = RTA_DATA(ifla);
    int i, srclen = RTA_PAYLOAD(ifla);
    char *p = dst;

    switch(type) {
        case ARPHRD_TUNNEL:
        case ARPHRD_IPGRE:
        case ARPHRD_SIT:
            if(srclen < 4)
                return(2);
            if(!inet_ntop(AF_INET, src, dst, dstlen))
                return(1);
            return(0);
        case ARPHRD_TUNNEL6:
#ifdef ARPHRD_IP6GRE
        case ARPHRD_IP6GRE:
#endif
            if(srclen < 16)
                return(2);
            if(!inet_ntop(AF_INET6, src, dst, dstlen))
                return(1);
            return(0);
    }

    for(i = 0; i < srclen; i++)
        if(p - dst < dstlen)
            p += snprintf(p, dstlen - strlen(dst), "%02x%s",
                src[i], (i + 1 == srclen) ? "" : ":");

    return(0);
}

/*
 * debug AF_* address attribute
 */
void debug_rta_af(int lev, struct rtattr *rta, const char *name,
    unsigned short family)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = inet_ntop_ifa(family, rta, addr, sizeof(addr));
    if(res) {
        rec_dbg(lev, "%s(%hu): -- %s --",
            name, RTA_ALIGN(rta->rta_len),
            (res == 1) ? strerror(errno) : "payload too short");
        return;
    }

    rec_dbg(lev, "%s(%hu): %s",
        name, RTA_ALIGN(rta->rta_len), addr);

    return;
}

/*
 * convert interface address from binary to text
 */
int inet_ntop_ifa(int family, struct rtattr *ifa, char *saddr, int slen)
{
    unsigned char *addr = (unsigned char *)RTA_DATA(ifa);
    int len = RTA_PAYLOAD(ifa);

    switch(family) {
        case AF_INET:
            if(len < 4)
                return(2);
            break;
        case AF_INET6:
            if(len < 16)
                return(2);
            break;
    }

    if(!inet_ntop(family, addr, saddr, slen))
        return(1);

    return(0);
}

/*
 * debug attribute
 */
void debug_rta_tc_addr(int lev, struct tcmsg *tcm, struct rtattr *rta, const char *name)
{
    char addr[INET6_ADDRSTRLEN+1] = "";
    int res;

    res = inet_ntop_tc_addr(tcm, rta, addr, sizeof(addr));
    if(res) {
        rec_dbg(lev, "%s(%hu): -- %s --",
            name, RTA_ALIGN(rta->rta_len),
            (res == 1) ? strerror(errno) : "payload too short");
        return;
    }

    rec_dbg(lev, "%s(%hu): %s", name, RTA_ALIGN(rta->rta_len), addr);
}

/*
 * convert interface address from binary to text
 */
int inet_ntop_tc_addr(struct tcmsg *tcm, struct rtattr *tca, char *saddr, int slen)
{
    int af = -1;
    unsigned char *addr = (unsigned char *)RTA_DATA(tca);
    int len = RTA_PAYLOAD(tca);

    switch(ntohs(TC_H_MIN(tcm->tcm_info))) {
        case ETH_P_IP:
            af = AF_INET;
            if(len < 4)
                return(2);
            break;
        case ETH_P_IPV6:
            af = AF_INET6;
            if(len < 16)
                return(2);
            break;
    }

    if(!inet_ntop(af, addr, saddr, slen))
        return(1);

    return(0);
}

/*
 * debug attribute TCA_*_CLASSID
 */
void debug_tca_classid(int lev, struct rtattr *tca, const char *name)
{
    unsigned n_classid;
    char s_classid[MAX_STR_SIZE] = "";

    if(debug_rta_len_chk(lev, tca, name, sizeof(n_classid)))
        return;

    n_classid = *(unsigned *)RTA_DATA(tca);
    parse_tc_handle(s_classid, sizeof(s_classid), n_classid);

    rec_dbg(lev, "%s(%hu): 0x%08x(%s)",
        name, RTA_ALIGN(tca->rta_len), n_classid, s_classid);
}

/*
 * parse qdisc handle
 */
void parse_tc_handle(char *p, int len, unsigned id)
{
    if (id == TC_H_ROOT)
        snprintf(p, len, "root");
    else if(id == TC_H_INGRESS)
        snprintf(p, len, "ingress");
    else if(id == TC_H_UNSPEC)
        snprintf(p, len, "none");
    else if(!TC_H_MAJ(id))
        snprintf(p, len, ":%x", TC_H_MIN(id));
    else if(!TC_H_MIN(id))
        snprintf(p, len, "%x:", TC_H_MAJ(id)>>16);
    else if(id)
        snprintf(p, len, "%x:%x", TC_H_MAJ(id)>>16, TC_H_MIN(id));
}
