/*
 * log.c - log function
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

static FILE *log_fd;

/*
 * open a log file
 */
int open_log(char *filename)
{
    int log_opts = get_log_opts();

    if(log_opts & L_LOCAL) {
        log_fd = fopen(filename, "a");
        if(log_fd == NULL) {
            fprintf(stderr, "[Error] %s: fopen(): %s\n", __func__, strerror(errno));
            fprintf(stderr, "[Error] %s: can't open log file(%s)\n", __func__, filename);
            return(-1);
        }
    }

    if(log_opts & L_SYSLOG) {
        openlog(PACKAGE_NAME, LOG_PID, get_facility());
    }

    return(0);
}

/*
 * concatnate logging messages
 */
char *add_log(char *msg, char *mp, char *format, ...)
{
    va_list ap_msg;
    int rc;

    if(!mp || mp - msg < 0 || mp - msg >= MAX_MSG_SIZE)
        return(NULL);

    va_start(ap_msg, format);
    rc = vsnprintf(mp, MAX_MSG_SIZE - (mp - msg), format, ap_msg);
    va_end(ap_msg);

    if(rc < 0) {
        rec_log("error: snprintf failed");
        return(NULL);
    }
    if(rc >= MAX_MSG_SIZE - (mp - msg)) {
        rec_log("error: message truncated");
        return(NULL);
    }
    mp += rc;

    return(mp);
}

/*
 * record logging messages
 */
void rec_log(char *format, ...)
{
    va_list ap_msg;
    char msg[MAX_MSG_SIZE] = "";
    int log_opts = get_log_opts();

    va_start(ap_msg, format);
    vsnprintf(msg, sizeof(msg), format, ap_msg);
    va_end(ap_msg);

    if(log_opts & L_LOCAL) {
        struct timeval tv;
        struct tm *tm;

        gettimeofday(&tv, NULL);
        tm = localtime(&tv.tv_sec);
        fprintf(log_fd, "[%04d-%02d-%02d %02d:%02d:%02d.%06ld] %s\n",
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec, msg);
        fflush(log_fd);
    }

    if(log_opts & L_SYSLOG)
        syslog(LOG_INFO, "%s", msg);
}

/*
 * close a log file
 */
void close_log(void)
{
    int log_opts = get_log_opts();

    if(log_opts & L_LOCAL) {
        if(log_fd)
            fclose(log_fd);
    }

    if(log_opts & L_SYSLOG) {
        closelog();
    }
}
