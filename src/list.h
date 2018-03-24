/*
 * list.h - linked list utility
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
#ifndef _LIST_H__
#define _LIST_H__

#include <stddef.h> /* offsetof() */

/* a list format */
struct list_head {
    struct list_head *next, *prev;
};

/*
 * get a struct for a specified entry
 */
#define list_entry(ptr, type, member) \
    (type *)((char *)ptr - offsetof(type, member))

/*
 * initialize a list
 */
static inline void list_init(struct list_head *list)
{
    list->next = list->prev = list;
}

/*
 * insert a new entry
 */
static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

/*
 * add a new entry before a specified entry
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}

/*
 * delete an entry
 */
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

/*
 * delete an entry from a list
 */
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    list_init(entry);
}

/*
 * delete from one list and add as another's head
 */
static inline void list_move(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add(list, head);
}

/*
 * iterate over a list
 */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/*
 * iterate over a list safe against removal of an entry
 */
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

#endif
