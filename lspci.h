/*
 *	The PCI Utilities -- List All PCI Devices
 *
 *	Copyright (c) 1997--2010 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#define PCIUTILS_LSPCI
#include "pciutils.h"

/*
 *  If we aren't being compiled by GCC, use xmalloc() instead of alloca().
 *  This increases our memory footprint, but only slightly since we don't
 *  use alloca() much.
 */
#if defined (__FreeBSD__) || defined (__NetBSD__) || defined (__OpenBSD__) || defined (__DragonFly__) || defined (__DJGPP__)
/* alloca() is defined in stdlib.h */
#elif defined(__GNUC__) && !defined(PCI_OS_WINDOWS)
#include <alloca.h>
#else
#undef alloca
#define alloca xmalloc
#endif

/*** Options ***/

extern int verbose;
extern struct pci_filter filter;
extern char *opt_pcimap;

/*** PCI devices and access to their config space ***/

struct device {
  struct device *next;
  struct pci_dev *dev;
  unsigned int config_cached, config_bufsize;
  byte *config;				/* Cached configuration space data */
  byte *present;			/* Maps which configuration bytes are present */
};

extern struct device *first_dev;
extern struct pci_access *pacc;

struct device *scan_device(struct pci_dev *p);
void show_device(struct device *d);

int config_fetch(struct device *d, unsigned int pos, unsigned int len);
u32 get_conf_long(struct device *d, unsigned int pos);
word get_conf_word(struct device *d, unsigned int pos);
byte get_conf_byte(struct device *d, unsigned int pos);

void get_subid(struct device *d, word *subvp, word *subdp);

/* Useful macros for decoding of bits and bit fields */

#define FLAG(x,y) ((x & y) ? '+' : '-')
#define BITS(x,at,width) (((x) >> (at)) & ((1 << (width)) - 1))
#define TABLE(tab,x,buf) ((x) < sizeof(tab)/sizeof((tab)[0]) ? (tab)[x] : (sprintf((buf), "??%d", (x)), (buf)))

/* ls-vpd.c */

void cap_vpd(struct device *d);

/* ls-caps.c */

void show_caps(struct device *d, int where);

/* ls-ecaps.c */

void show_ext_caps(struct device *d, int type);

/* ls-caps-vendor.c */

void show_vendor_caps(struct device *d, int where, int cap);

/* ls-info.c */

enum info_val_type {
    INFO_VAL_STRING,
    INFO_VAL_OBJECT,
    INFO_VAL_LIST,
    INFO_VAL_FLAG
};

struct info_obj {
  struct info_pair *pair;
};

union info_val {
  char *str;
  struct info_obj *obj;
  struct info_list *list;
  char flag;
};

struct info_pair {
  char *key;
  enum info_val_type type;
  union info_val val;
  struct info_pair *next;
};

struct info_list {
  enum info_val_type type;
  struct info_list_node *node;
};

struct info_list_node {
  union info_val val;
  struct info_list_node *next;
};

struct info_obj *info_obj_create(void);
struct info_obj *info_obj_create_in_obj(struct info_obj *parent_obj, char *key);
void info_obj_add_str(struct info_obj *obj, const char *key, const char *str);
void info_obj_add_list(struct info_obj *obj, const char *key, struct info_list *list);
void info_obj_add_obj(struct info_obj *obj, const char *key, struct info_obj *new_obj);
void info_obj_add_flag(struct info_obj *obj, const char *key, char flag);
void info_obj_add_fmt_str(struct info_obj *obj, const char *key, size_t size, const char *fmt, ...);
void info_obj_add_fmt_buf_str(struct info_obj *obj, const char *key, char *buf, size_t size, const char *fmt, ...);
void info_obj_print_json(struct info_obj *obj, int ind_lvl);
void info_obj_delete_pair(struct info_obj *obj, char *key);
void info_obj_delete(struct info_obj *obj);

struct info_list *info_list_create(enum info_val_type type);
struct info_list *info_list_create_in_obj(struct info_obj *parent_obj, char *key, enum info_val_type type);
void info_list_add_str(struct info_list *list, const char *str);
void info_list_add_obj(struct info_list *list, struct info_obj *obj);

/* ls-kernel.c */

void show_kernel_machine(struct device *d UNUSED);
void show_kernel(struct device *d UNUSED);
void show_kernel_cleanup(void);
void fill_info_kernel(struct info_obj *dev_obj UNUSED, struct device *d UNUSED);

/* ls-tree.c */

void show_forest(void);

/* ls-map.c */

void map_the_bus(void);
