/*
 * debug.c - debug function
 * Copyright (C) 2011-2024 Tetsumune KISO <t2mune@gmail.com>
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

static FILE *dbg_fd;

/*
 * open a debug file
 */
int open_dbg(char *filename)
{
    dbg_fd = fopen(filename, "a");
    if(dbg_fd == NULL) {
        fprintf(stderr, "[Error] %s: fopen(): %s\n", __func__, strerror(errno));
        fprintf(stderr, "[Error] %s: can't open debug file(%s)\n", __func__, filename);
        return(-1);
    }

    return(0);
}

/*
 * record debug messages
 */
void rec_dbg(int level, char *format, ...)
{
    va_list ap;
    struct timeval tv;
    struct tm *tm;
    char msg[MAX_MSG_SIZE] = "";
    char indent[MAX_STR_SIZE] = "";
    int i;

    for(i = 0; i < level; i++)
        strncat(indent, "    ", sizeof(indent)-1);

    va_start(ap, format);

    vsnprintf(msg, sizeof(msg), format, ap);

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);

    fprintf(dbg_fd, "[%04d-%02d-%02d %02d:%02d:%02d.%06ld] %s%s\n",
        tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec,
        indent, msg);
    fflush(dbg_fd);

    va_end(ap);
}

/*
 * close a debug file
 */
void close_dbg(void)
{
    if(dbg_fd)
        fclose(dbg_fd);
}
