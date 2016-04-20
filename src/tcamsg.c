/*
 * tcamsg.c - traffic control message parser
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
 * parse traffic control message
 */
int parse_tcamsg(struct nlmsghdr *nlh)
{
    struct tcamsg *tcam;
    int tcam_len;
    struct rtattr *tcaa[TCAA_MAX+1];
    char msg[MAX_MSG_SIZE] = "";
    char *mp = msg;
    int log_opts = get_log_opts();

    /* debug nlmsghdr */
    if(log_opts & L_DEBUG)
        debug_nlmsg(0, nlh);

    /* get tcamsg */
    tcam_len = NLMSG_PAYLOAD(nlh, 0);
    if(tcam_len < sizeof(*tcam)) {
        rec_log("error: %s: length too short", __func__);
        return(1);
    }
    tcam = (struct tcamsg *)NLMSG_DATA(nlh);

    /* parse traffic control action message attributes */
    parse_tca(tcaa, nlh);

    /* debug tcamsg */
    if(log_opts & L_DEBUG)
        debug_tcamsg(0, tcam, tcaa, tcam_len);

    /* kind of message */
    switch(nlh->nlmsg_type) {
        case RTM_NEWACTION:
            mp = add_log(msg, mp, "tc action added: ");
            break;
        case RTM_DELACTION:
            mp = add_log(msg, mp, "tc action deleted: ");
            break;
        default:
            return(1);
    }

    if(tcaa[TCA_ACT_TAB])
        if(parse_tca_acts(msg, mp, tcaa[TCA_ACT_TAB]))
            return(1);

    return(0);
}

/*
 * parse actions
 */
int parse_tca_acts(char *msg, char *mp, struct rtattr *tcaa)
{
    struct rtattr *acts[TCA_ACT_MAX_PRIO+1];

    parse_nested_rtattr(acts, TCA_ACT_MAX_PRIO, tcaa);

    /* logging for each action */
    int i;

    for(i = 0; i < TCA_ACT_MAX_PRIO; i++)
        if(acts[i] && parse_tca_act(msg, mp, acts[i]))
            return(1);

    return(0);
}

/*
 * parse attributes TCA_ACT_*
 */
int parse_tca_act(char *msg, char *mp, struct rtattr *acts)
{
    struct rtattr *act[__TCA_ACT_MAX];
    char kind[IFNAMSIZ] = "";

    mp = add_log(msg, mp, "order=%d ", acts->rta_type);

    parse_nested_rtattr(act, __TCA_ACT_MAX-1, acts);

    if(act[TCA_ACT_KIND]) {
        strncpy(kind, (char *)RTA_DATA(act[TCA_ACT_KIND]), sizeof(kind));
        mp = add_log(msg, mp, "action=%s ", kind);
    }

    if(act[TCA_ACT_OPTIONS]) {
        if(!strncmp(kind, "police", sizeof(kind))) {
            if(parse_tca_act_options_police(msg, mp, act[TCA_ACT_OPTIONS]))
                return(1);
            return(0);
        } else if(!strncmp(kind, "gact", sizeof(kind))) {
            if(parse_tca_act_options_gact(msg, mp, act[TCA_ACT_OPTIONS]))
                return(1);
            return(0);
        } else if(!strncmp(kind, "pedit", sizeof(kind))) {
            if(parse_tca_act_options_pedit(msg, mp, act[TCA_ACT_OPTIONS]))
                return(1);
            return(0);
        } else if(!strncmp(kind, "mirred", sizeof(kind))) {
            if(parse_tca_act_options_mirred(msg, mp, act[TCA_ACT_OPTIONS]))
                return(1);
            return(0);
#ifdef HAVE_LINUX_TC_ACT_TC_NAT_H
        } else if(!strncmp(kind, "nat", sizeof(kind))) {
            if(parse_tca_act_options_nat(msg, mp, act[TCA_ACT_OPTIONS]))
                return(1);
            return(0);
#endif
#ifdef HAVE_LINUX_TC_ACT_TC_SKBEDIT_H
        } else if(!strncmp(kind, "skbedit", sizeof(kind))) {
            if(parse_tca_act_options_skbedit(msg, mp, act[TCA_ACT_OPTIONS]))
                return(1);
            return(0);
#endif
#ifdef HAVE_LINUX_TC_ACT_TC_CSUM_H
        } else if(!strncmp(kind, "csum", sizeof(kind))) {
            if(parse_tca_act_options_csum(msg, mp, act[TCA_ACT_OPTIONS]))
                return(1);
            return(0);
#endif
        }
    }

    rec_log("%s", msg);

    return(0);
}

/*
 * debug traffic control action message
 */
void debug_tcamsg(int lev, struct tcamsg *tcam, struct rtattr *tcaa[], int tcam_len)
{
    /* debug tcamsg */
    rec_dbg(lev, "*********************************************************************");

    rec_dbg(lev, "[ tcamsg(%d) ]",
        NLMSG_ALIGN(sizeof(*tcam)));
    rec_dbg(lev, "    tca_family(%d): 0x%02x(%s)",
        sizeof(tcam->tca_family), tcam->tca_family,
        conv_af_type(tcam->tca_family, 1));
    rec_dbg(lev, "    tca__pad1(%d): 0x%02x",
        sizeof(tcam->tca__pad1), tcam->tca__pad1);
    rec_dbg(lev, "    tca__pad2(%d): 0x%04x",
        sizeof(tcam->tca__pad2), tcam->tca__pad2);

    /* debug traffic control action attributes */
    rec_dbg(lev,"*********************************************************************");
    rec_dbg(lev, "[ tcamsg attributes(%d) ]",
            NLMSG_ALIGN(tcam_len - NLMSG_ALIGN(sizeof(*tcam))));

    if(tcaa[TCA_ACT_TAB])
        debug_tca_acts(lev+1, tcaa[TCA_ACT_TAB],
            "TCA_ACT_TAB");

    rec_dbg(lev, "");
}

/*
 * debug attributes of multiple actions
 */
void debug_tca_acts(int lev, struct rtattr *tcaa, const char *name)
{
    struct rtattr *acts[TCA_ACT_MAX_PRIO+1];
    int i;

    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(tcaa->rta_len)); 

    parse_nested_rtattr(acts, TCA_ACT_MAX_PRIO, tcaa);

    for(i = 0; i < TCA_ACT_MAX_PRIO; i++)
        if(acts[i]) {
            rec_dbg(lev+1, "acts[%hu](%hu):", acts[i]->rta_type, acts[i]->rta_len);
            debug_tca_act(lev+1, acts[i]);
        }
}

/*
 * debug attributes TCA_ACT_*
 */
void debug_tca_act(int lev, struct rtattr *acts)
{
    struct rtattr *act[__TCA_ACT_MAX];
    char kind[IFNAMSIZ];

    parse_nested_rtattr(act, __TCA_ACT_MAX-1, acts);

    if(act[TCA_ACT_KIND])
        debug_rta_str(lev+1, act[TCA_ACT_KIND], 
            "TCA_ACT_KIND", kind, sizeof(kind));

    if(act[TCA_ACT_OPTIONS])
        debug_tca_act_options(lev+1, act[TCA_ACT_OPTIONS],
            "TCA_ACT_OPTIONS", kind, sizeof(kind));

    if(act[TCA_ACT_INDEX])
        debug_rta_s32(lev+1, act[TCA_ACT_INDEX],
            "TCA_ACT_INDEX", NULL);

    if(act[TCA_ACT_STATS])
        debug_tca_act_stats(lev+1, act[TCA_ACT_STATS],
            "TCA_ACT_STATS");
}

/*
 * debug attribute TCA_ACT_OPTIONS
 */
void debug_tca_act_options(int lev, struct rtattr *act,
    const char *name, char *kind, int len)
{
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(act->rta_len));

    if(!strncmp(kind, "police", len))
        debug_tca_act_options_police(lev, act, NULL);
    else if(!strncmp(kind, "gact", len))
        debug_tca_act_options_gact(lev, act);
    else if(!strncmp(kind, "pedit", len))
        debug_tca_act_options_pedit(lev, act);
    else if(!strncmp(kind, "mirred", len))
        debug_tca_act_options_mirred(lev, act);
#ifdef HAVE_LINUX_TC_ACT_TC_NAT_H
    else if(!strncmp(kind, "nat", len))
        debug_tca_act_options_nat(lev, act);
#endif
#ifdef HAVE_LINUX_TC_ACT_TC_SKBEDIT_H
    else if(!strncmp(kind, "skbedit", len))
        debug_tca_act_options_skbedit(lev, act);
#endif
#ifdef HAVE_LINUX_TC_ACT_TC_CSUM_H
    else if(!strncmp(kind, "csum", len))
        debug_tca_act_options_csum(lev, act);
#endif
    else
        rec_dbg(lev, "    -- unknown action %s --", kind);
}

/*
 * debug attribute TCA_ACT_STATS
 */
void debug_tca_act_stats(int lev, struct rtattr *act, const char *name)
{
    rec_dbg(lev, "%s(%hu):", name, RTA_ALIGN(act->rta_len));
    debug_tca_stats2_attr(lev, act);
}

/*
 * debug tcf_t
 */
void debug_tcf_t(int lev, struct tcf_t *tm)
{ 
    rec_dbg(lev, "[ tcf_t(%d) ]", sizeof(*tm));
    rec_dbg(lev, "    install(%d): 0x%016x",
        sizeof(tm->install), tm->install);
    rec_dbg(lev, "    lastuse(%d): 0x%016x",
        sizeof(tm->lastuse), tm->lastuse);
    rec_dbg(lev, "    expires(%d): 0x%016x",
        sizeof(tm->expires), tm->expires);
}

/*
 * convert TC_ACT_* action for debug
 */
const char *conv_tc_action(int action, unsigned char debug)
{
#define _TC_ACTION(s1, s2) \
    if(action == TC_ACT_##s1) \
        return(debug ? #s1 : #s2);
    _TC_ACTION(UNSPEC, continue);
    _TC_ACTION(OK, ok);
    _TC_ACTION(RECLASSIFY, reclassify);
    _TC_ACTION(SHOT, drop);
    _TC_ACTION(PIPE, pipe);
    _TC_ACTION(STOLEN, stolen);
    _TC_ACTION(QUEUED, queued);
    _TC_ACTION(REPEAT, repeat);
    _TC_ACTION(JUMP, jump);
#undef _TC_ACTION
    return(debug ? "UNKNOWN" : "unknown");
}
