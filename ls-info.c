/*
 *	The PCI Utilities -- Save PCI info
 *
 *	Copyright (c) 2017 Virtuozzo International GmbH
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "lspci.h"

struct info_list *
info_list_create(enum info_val_type type)
{
  struct info_list *list = xmalloc(sizeof(struct info_list));

  list->node = NULL;
  list->type = type;

  return list;
}

struct info_list *
info_list_create_in_obj(struct info_obj *parent_obj, char *key, enum info_val_type type)
{
  struct info_list *list = info_list_create(type);

  info_obj_add_list(parent_obj, key, list);

  return list;
}

static void
info_list_delete(struct info_list *list)
{
  struct info_list_node *node = list->node, *next;

  while (node)
    {
      switch (list->type)
	{
	case INFO_VAL_STRING:
	  free(node->val.str);
	  break;
	case INFO_VAL_LIST:
	  info_list_delete(node->val.list);
	  break;
	case INFO_VAL_OBJECT:
	  info_obj_delete(node->val.obj);
	  break;
	default:
	  break;
	}
      next = node->next;
      free(node);
      node = next;
    }
  free(list);
}

struct info_obj *
info_obj_create(void)
{
  struct info_obj *obj = xmalloc(sizeof(struct info_obj));

  obj->pair = NULL;

  return obj;
}

struct info_obj *
info_obj_create_in_obj(struct info_obj *parent_obj, char *key)
{
  struct info_obj *obj = info_obj_create();

  info_obj_add_obj(parent_obj, key, obj);

  return obj;
}

static void
info_pair_delete(struct info_pair *pair)
{
  switch (pair->type)
  {
  case INFO_VAL_STRING:
    free(pair->val.str);
    break;
  case INFO_VAL_LIST:
    info_list_delete(pair->val.list);
    break;
  case INFO_VAL_OBJECT:
    info_obj_delete(pair->val.obj);
    break;
  default:
    break;
  }
  free(pair->key);
  free(pair);
}

void
info_obj_delete(struct info_obj *obj)
{
  struct info_pair *pair = obj->pair, *next;

  while (pair)
    {
      next = pair->next;
      info_pair_delete(pair);
      pair = next;
    }
  free(obj);
}

void
info_obj_delete_pair(struct info_obj *obj, char *key)
{
  struct info_pair *pair = obj->pair, *next, *prev = NULL;

  while (pair)
    {
      next = pair->next;
      if (!strcmp(pair->key, key))
	{
	  info_pair_delete(pair);
	  if (prev)
	    prev->next = next;
	  else
	    obj->pair = next;
	  break;
	}
      prev = pair;
      pair = next;
   }
}

static struct info_list_node *
info_list_add_node(struct info_list *list)
{
  struct info_list_node *new_node = xmalloc(sizeof(struct info_list_node));

  new_node->next = NULL;

  if (list->node)
    {
      struct info_list_node *node;

      for (node = list->node; node && node->next; node = node->next);
      node->next = new_node;
    }
  else
    list->node = new_node;

  return new_node;
}

void
info_list_add_str(struct info_list *list, const char *str)
{
  struct info_list_node *new_node = info_list_add_node(list);

  new_node->val.str = xstrdup(str);
}

void
info_list_add_obj(struct info_list *list, struct info_obj *obj)
{
  struct info_list_node *new_node = info_list_add_node(list);

  new_node->val.obj = obj;
}

static struct info_pair *
info_obj_add_pair(struct info_obj *obj, const char *key, enum info_val_type type)
{
  struct info_pair *new_pair = xmalloc(sizeof(struct info_pair));
  new_pair->key = xstrdup(key);
  new_pair->next = NULL;
  new_pair->type = type;

  if (obj->pair)
    {
      struct info_pair *pair;

      for (pair = obj->pair; pair && pair->next; pair = pair->next);
      pair->next = new_pair;
    }
  else
    obj->pair = new_pair;

  return new_pair;
}

void
info_obj_add_flag(struct info_obj *obj, const char *key, char flag)
{
  struct info_pair *new_pair = info_obj_add_pair(obj, key, INFO_VAL_FLAG);

  new_pair->val.flag = flag;
}

void
info_obj_add_str(struct info_obj *obj, const char *key, const char *str)
{
  struct info_pair *new_pair = info_obj_add_pair(obj, key, INFO_VAL_STRING);

  new_pair->val.str = xstrdup(str);
}

void
info_obj_add_fmt_buf_str(struct info_obj *obj, const char *key, char *buf, size_t size, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, size, fmt, ap);
  va_end(ap);

  info_obj_add_str(obj, key, buf);
}

void
info_obj_add_fmt_str(struct info_obj *obj, const char *key, size_t size, const char *fmt, ...)
{
  va_list ap;
  char *buf = xmalloc(size);

  va_start(ap, fmt);
  vsnprintf(buf, size, fmt, ap);
  va_end(ap);

  info_obj_add_str(obj, key, buf);
  free(buf);
}

void
info_obj_add_list(struct info_obj *obj, const char *key, struct info_list *list)
{
  struct info_pair *new_pair = info_obj_add_pair(obj, key, INFO_VAL_LIST);

  new_pair->val.list = list;
}

void
info_obj_add_obj(struct info_obj *obj, const char *key, struct info_obj *new_obj)
{
  struct info_pair *new_pair = info_obj_add_pair(obj, key, INFO_VAL_OBJECT);

  new_pair->val.obj = new_obj;
}

static void
info_pair_print_json(struct info_pair *pair, int ind_lvl);
static void
info_list_node_print_json(struct info_list_node *node, enum info_val_type type, int ind_lvl);

static void
print_ind(int ind_lvl)
{
  int i;

  putchar('\n');
  for (i = 0; i < ind_lvl; i++)
    fputs("  ", stdout);
}

void
info_obj_print_json(struct info_obj *obj, int ind_lvl)
{
  struct info_pair *pair;

  printf("{");
  for (pair = obj->pair; pair; pair = pair->next)
    {
      info_pair_print_json(pair, ind_lvl+1);
      if (pair->next)
	printf(", ");
    }
  if (obj->pair) /* Do not indent if object was empty */
    print_ind(ind_lvl);
  printf("}");
}

static
void info_list_print_json(struct info_list *list, int ind_lvl)
{
  struct info_list_node *node;

  printf("[");
  for (node = list->node; node; node = node->next)
    {
      info_list_node_print_json(node, list->type, ind_lvl+1);
      if (node->next)
	printf(", ");
    }
  if (list->node) /* Do not indent if list was empty */
    print_ind(ind_lvl);
  printf("]");
}

static void
info_list_node_print_json(struct info_list_node *node, enum info_val_type type, int ind_lvl)
{
  print_ind(ind_lvl);
  switch (type)
    {
    case INFO_VAL_STRING:
      printf("\"%s\"", node->val.str);
      break;
    case INFO_VAL_LIST:
      info_list_print_json(node->val.list, ind_lvl);
      break;
    case INFO_VAL_OBJECT:
      info_obj_print_json(node->val.obj, ind_lvl);
      break;
    case INFO_VAL_FLAG:
      printf("%s", node->val.flag ? "true" : "false");
      break;
    default:
      break;
    }
}

static void
info_pair_print_json(struct info_pair *pair, int ind_lvl)
{
  print_ind(ind_lvl);
  printf("\"%s\": ", pair->key);
  switch (pair->type)
    {
    case INFO_VAL_STRING:
      printf("\"%s\"", pair->val.str);
      break;
    case INFO_VAL_LIST:
      info_list_print_json(pair->val.list, ind_lvl);
      break;
    case INFO_VAL_OBJECT:
      info_obj_print_json(pair->val.obj, ind_lvl);
      break;
    case INFO_VAL_FLAG:
      printf("%s", (pair->val.flag == '+') ? "true" :
		   ((pair->val.flag == '-') ? "false" : "null"));
      break;
    default:
      break;
    }
}
