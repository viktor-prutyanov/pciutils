/*
 *	The PCI Utilities -- List All PCI Devices
 *
 *	Copyright (c) 1997--2016 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "lspci.h"

/* Options */

int verbose;				/* Show detailed information */
static int opt_hex;			/* Show contents of config space as hexadecimal numbers */
struct pci_filter filter;		/* Device filter */
static int opt_tree;			/* Show bus tree */
static int opt_machine;			/* Generate machine-readable output */
static int opt_map_mode;		/* Bus mapping mode enabled */
static int opt_domains;			/* Show domain numbers (0=disabled, 1=auto-detected, 2=requested) */
static int opt_kernel;			/* Show kernel drivers */
static int opt_query_dns;		/* Query the DNS (0=disabled, 1=enabled, 2=refresh cache) */
static int opt_query_all;		/* Query the DNS for all entries */
static int opt_json;
char *opt_pcimap;			/* Override path to Linux modules.pcimap */

const char program_name[] = "lspci";

static char options[] = "nvbxs:d:ti:mgp:qkJMDQ" GENERIC_OPTIONS ;

static char help_msg[] =
"Usage: lspci [<switches>]\n"
"\n"
"Basic display modes:\n"
"-mm\t\tProduce machine-readable output (single -m for an obsolete format)\n"
"-t\t\tShow bus tree\n"
"\n"
"Display options:\n"
"-v\t\tBe verbose (-vv for very verbose)\n"
#ifdef PCI_OS_LINUX
"-k\t\tShow kernel drivers handling each device\n"
#endif
"-x\t\tShow hex-dump of the standard part of the config space\n"
"-xxx\t\tShow hex-dump of the whole config space (dangerous; root only)\n"
"-xxxx\t\tShow hex-dump of the 4096-byte extended config space (root only)\n"
"-b\t\tBus-centric view (addresses and IRQ's as seen by the bus)\n"
"-D\t\tAlways show domain numbers\n"
"-J\t\tUse JSON output format\n"
"\n"
"Resolving of device ID's to names:\n"
"-n\t\tShow numeric ID's\n"
"-nn\t\tShow both textual and numeric ID's (names & numbers)\n"
#ifdef PCI_USE_DNS
"-q\t\tQuery the PCI ID database for unknown ID's via DNS\n"
"-qq\t\tAs above, but re-query locally cached entries\n"
"-Q\t\tQuery the PCI ID database for all ID's via DNS\n"
#endif
"\n"
"Selection of devices:\n"
"-s [[[[<domain>]:]<bus>]:][<slot>][.[<func>]]\tShow only devices in selected slots\n"
"-d [<vendor>]:[<device>][:<class>]\t\tShow only devices with specified ID's\n"
"\n"
"Other options:\n"
"-i <file>\tUse specified ID database instead of %s\n"
#ifdef PCI_OS_LINUX
"-p <file>\tLook up kernel modules in a given file instead of default modules.pcimap\n"
#endif
"-M\t\tEnable `bus mapping' mode (dangerous; root only)\n"
"\n"
"PCI access options:\n"
GENERIC_HELP
;

/*** Our view of the PCI bus ***/

struct pci_access *pacc;
struct device *first_dev;
static int seen_errors;

int
config_fetch(struct device *d, unsigned int pos, unsigned int len)
{
  unsigned int end = pos+len;
  int result;

  while (pos < d->config_bufsize && len && d->present[pos])
    pos++, len--;
  while (pos+len <= d->config_bufsize && len && d->present[pos+len-1])
    len--;
  if (!len)
    return 1;

  if (end > d->config_bufsize)
    {
      int orig_size = d->config_bufsize;
      while (end > d->config_bufsize)
	d->config_bufsize *= 2;
      d->config = xrealloc(d->config, d->config_bufsize);
      d->present = xrealloc(d->present, d->config_bufsize);
      memset(d->present + orig_size, 0, d->config_bufsize - orig_size);
    }
  result = pci_read_block(d->dev, pos, d->config + pos, len);
  if (result)
    memset(d->present + pos, 1, len);
  return result;
}

struct device *
scan_device(struct pci_dev *p)
{
  struct device *d;

  if (p->domain && !opt_domains)
    opt_domains = 1;
  if (!pci_filter_match(&filter, p))
    return NULL;
  d = xmalloc(sizeof(struct device));
  memset(d, 0, sizeof(*d));
  d->dev = p;
  d->config_cached = d->config_bufsize = 64;
  d->config = xmalloc(64);
  d->present = xmalloc(64);
  memset(d->present, 1, 64);
  if (!pci_read_block(p, 0, d->config, 64))
    {
      fprintf(stderr, "lspci: Unable to read the standard configuration space header of device %04x:%02x:%02x.%d\n",
	      p->domain, p->bus, p->dev, p->func);
      seen_errors++;
      return NULL;
    }
  if ((d->config[PCI_HEADER_TYPE] & 0x7f) == PCI_HEADER_TYPE_CARDBUS)
    {
      /* For cardbus bridges, we need to fetch 64 bytes more to get the
       * full standard header... */
      if (config_fetch(d, 64, 64))
	d->config_cached += 64;
    }
  pci_setup_cache(p, d->config, d->config_cached);
  pci_fill_info(p, PCI_FILL_IDENT | PCI_FILL_CLASS);
  return d;
}

static void
scan_devices(void)
{
  struct device *d;
  struct pci_dev *p;

  pci_scan_bus(pacc);
  for (p=pacc->devices; p; p=p->next)
    if (d = scan_device(p))
      {
	d->next = first_dev;
	first_dev = d;
      }
}

/*** Config space accesses ***/

static void
check_conf_range(struct device *d, unsigned int pos, unsigned int len)
{
  while (len)
    if (!d->present[pos])
      die("Internal bug: Accessing non-read configuration byte at position %x", pos);
    else
      pos++, len--;
}

byte
get_conf_byte(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 1);
  return d->config[pos];
}

word
get_conf_word(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 2);
  return d->config[pos] | (d->config[pos+1] << 8);
}

u32
get_conf_long(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 4);
  return d->config[pos] |
    (d->config[pos+1] << 8) |
    (d->config[pos+2] << 16) |
    (d->config[pos+3] << 24);
}

/*** Sorting ***/

static int
compare_them(const void *A, const void *B)
{
  const struct pci_dev *a = (*(const struct device **)A)->dev;
  const struct pci_dev *b = (*(const struct device **)B)->dev;

  if (a->domain < b->domain)
    return -1;
  if (a->domain > b->domain)
    return 1;
  if (a->bus < b->bus)
    return -1;
  if (a->bus > b->bus)
    return 1;
  if (a->dev < b->dev)
    return -1;
  if (a->dev > b->dev)
    return 1;
  if (a->func < b->func)
    return -1;
  if (a->func > b->func)
    return 1;
  return 0;
}

static void
sort_them(void)
{
  struct device **index, **h, **last_dev;
  int cnt;
  struct device *d;

  cnt = 0;
  for (d=first_dev; d; d=d->next)
    cnt++;
  h = index = alloca(sizeof(struct device *) * cnt);
  for (d=first_dev; d; d=d->next)
    *h++ = d;
  qsort(index, cnt, sizeof(struct device *), compare_them);
  last_dev = &first_dev;
  h = index;
  while (cnt--)
    {
      *last_dev = *h;
      last_dev = &(*h)->next;
      h++;
    }
  *last_dev = NULL;
}

/*** Normal output ***/

static void
show_slot_name(struct device *d)
{
  struct pci_dev *p = d->dev;

  if (!opt_machine ? opt_domains : (p->domain || opt_domains >= 2))
    printf("%04x:", p->domain);
  printf("%02x:%02x.%d", p->bus, p->dev, p->func);
}

static void
fill_slot_name(struct device *d, char *buf, size_t size)
{
  struct pci_dev *p = d->dev;

  if (!opt_machine ? opt_domains : (p->domain || opt_domains >= 2))
    snprintf(buf, size, "%04x:", p->domain);
  snprintf(buf, size, "%02x:%02x.%d", p->bus, p->dev, p->func);
}

void
get_subid(struct device *d, word *subvp, word *subdp)
{
  byte htype = get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f;

  if (htype == PCI_HEADER_TYPE_NORMAL)
    {
      *subvp = get_conf_word(d, PCI_SUBSYSTEM_VENDOR_ID);
      *subdp = get_conf_word(d, PCI_SUBSYSTEM_ID);
    }
  else if (htype == PCI_HEADER_TYPE_CARDBUS && d->config_cached >= 128)
    {
      *subvp = get_conf_word(d, PCI_CB_SUBSYSTEM_VENDOR_ID);
      *subdp = get_conf_word(d, PCI_CB_SUBSYSTEM_ID);
    }
  else
    *subvp = *subdp = 0xffff;
}

static void
show_terse(struct device *d)
{
  int c;
  struct pci_dev *p = d->dev;
  char classbuf[128], devbuf[128];

  show_slot_name(d);
  printf(" %s: %s",
	 pci_lookup_name(pacc, classbuf, sizeof(classbuf),
			 PCI_LOOKUP_CLASS,
			 p->device_class),
	 pci_lookup_name(pacc, devbuf, sizeof(devbuf),
			 PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
			 p->vendor_id, p->device_id));
  if (c = get_conf_byte(d, PCI_REVISION_ID))
    printf(" (rev %02x)", c);
  if (verbose)
    {
      char *x;
      c = get_conf_byte(d, PCI_CLASS_PROG);
      x = pci_lookup_name(pacc, devbuf, sizeof(devbuf),
			  PCI_LOOKUP_PROGIF | PCI_LOOKUP_NO_NUMBERS,
			  p->device_class, c);
      if (c || x)
	{
	  printf(" (prog-if %02x", c);
	  if (x)
	    printf(" [%s]", x);
	  putchar(')');
	}
    }
  putchar('\n');

  if (verbose || opt_kernel)
    {
      word subsys_v, subsys_d;
      char ssnamebuf[256];

      if (p->label)
        printf("\tDeviceName: %s", p->label);
      get_subid(d, &subsys_v, &subsys_d);
      if (subsys_v && subsys_v != 0xffff)
	printf("\tSubsystem: %s\n",
		pci_lookup_name(pacc, ssnamebuf, sizeof(ssnamebuf),
			PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
			p->vendor_id, p->device_id, subsys_v, subsys_d));
    }
}

/*** Verbose output ***/

static void
show_size(u64 x)
{
  static const char suffix[][2] = { "", "K", "M", "G", "T" };
  unsigned i;
  if (!x)
    return;
  for (i = 0; i < (sizeof(suffix) / sizeof(*suffix) - 1); i++) {
    if (x % 1024)
      break;
    x /= 1024;
  }
  printf(" [size=%u%s]", (unsigned)x, suffix[i]);
}

static void
fill_size(char *buf, size_t size, u64 x)
{
  static const char suffix[][2] = { "", "K", "M", "G", "T" };
  unsigned i;
  if (!x)
    {
      snprintf(buf, size, "0");
      return;
    }
  for (i = 0; i < (sizeof(suffix) / sizeof(*suffix) - 1); i++) {
    if (x % 1024)
      break;
    x /= 1024;
  }
  snprintf(buf, size, "%u%s", (unsigned)x, suffix[i]);
}

static void
show_range(char *prefix, u64 base, u64 limit, int is_64bit)
{
  if (base > limit)
    {
      if (!verbose)
	return;
      else if (verbose < 3)
	{
	  printf("%s: None\n", prefix);
	  return;
	}
    }

  printf("%s: ", prefix);
  if (is_64bit)
    printf("%016" PCI_U64_FMT_X "-%016" PCI_U64_FMT_X, base, limit);
  else
    printf("%08x-%08x", (unsigned) base, (unsigned) limit);
  if (base <= limit)
    show_size(limit - base + 1);
  else
    printf(" [empty]");
  putchar('\n');
}

static void
fill_range(char *buf, size_t size, u64 base, u64 limit, int is_64bit)
{
  if (base > limit)
    {
      snprintf(buf, size, "None");
      return;
    }

  if (is_64bit)
    snprintf(buf, size, "%016" PCI_U64_FMT_X "-%016" PCI_U64_FMT_X, base, limit);
  else
    snprintf(buf, size, "%08x-%08x", (unsigned) base, (unsigned) limit);
}

static void
show_bases(struct device *d, int cnt)
{
  struct pci_dev *p = d->dev;
  word cmd = get_conf_word(d, PCI_COMMAND);
  int i;
  int virtual = 0;

  for (i=0; i<cnt; i++)
    {
      pciaddr_t pos = p->base_addr[i];
      pciaddr_t len = (p->known_fields & PCI_FILL_SIZES) ? p->size[i] : 0;
      pciaddr_t ioflg = (p->known_fields & PCI_FILL_IO_FLAGS) ? p->flags[i] : 0;
      u32 flg = get_conf_long(d, PCI_BASE_ADDRESS_0 + 4*i);
      if (flg == 0xffffffff)
	flg = 0;
      if (!pos && !flg && !len)
	continue;
      if (verbose > 1)
	printf("\tRegion %d: ", i);
      else
	putchar('\t');
      if (ioflg & PCI_IORESOURCE_PCI_EA_BEI)
	  printf("[enhanced] ");
      else if (pos && !flg)	/* Reported by the OS, but not by the device */
	{
	  printf("[virtual] ");
	  flg = pos;
	  virtual = 1;
	}
      if (flg & PCI_BASE_ADDRESS_SPACE_IO)
	{
	  pciaddr_t a = pos & PCI_BASE_ADDRESS_IO_MASK;
	  printf("I/O ports at ");
	  if (a || (cmd & PCI_COMMAND_IO))
	    printf(PCIADDR_PORT_FMT, a);
	  else if (flg & PCI_BASE_ADDRESS_IO_MASK)
	    printf("<ignored>");
	  else
	    printf("<unassigned>");
	  if (!virtual && !(cmd & PCI_COMMAND_IO))
	    printf(" [disabled]");
	}
      else
	{
	  int t = flg & PCI_BASE_ADDRESS_MEM_TYPE_MASK;
	  pciaddr_t a = pos & PCI_ADDR_MEM_MASK;
	  int done = 0;
	  u32 z = 0;

	  printf("Memory at ");
	  if (t == PCI_BASE_ADDRESS_MEM_TYPE_64)
	    {
	      if (i >= cnt - 1)
		{
		  printf("<invalid-64bit-slot>");
		  done = 1;
		}
	      else
		{
		  i++;
		  z = get_conf_long(d, PCI_BASE_ADDRESS_0 + 4*i);
		}
	    }
	  if (!done)
	    {
	      if (a)
		printf(PCIADDR_T_FMT, a);
	      else
		printf(((flg & PCI_BASE_ADDRESS_MEM_MASK) || z) ? "<ignored>" : "<unassigned>");
	    }
	  printf(" (%s, %sprefetchable)",
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_32) ? "32-bit" :
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_64) ? "64-bit" :
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_1M) ? "low-1M" : "type 3",
		 (flg & PCI_BASE_ADDRESS_MEM_PREFETCH) ? "" : "non-");
	  if (!virtual && !(cmd & PCI_COMMAND_MEMORY))
	    printf(" [disabled]");
	}
      show_size(len);
      putchar('\n');
    }
}

static void
show_rom(struct device *d, int reg)
{
  struct pci_dev *p = d->dev;
  pciaddr_t rom = p->rom_base_addr;
  pciaddr_t len = (p->known_fields & PCI_FILL_SIZES) ? p->rom_size : 0;
  pciaddr_t ioflg = (p->known_fields & PCI_FILL_IO_FLAGS) ? p->rom_flags : 0;
  u32 flg = get_conf_long(d, reg);
  word cmd = get_conf_word(d, PCI_COMMAND);
  int virtual = 0;

  if (!rom && !flg && !len)
    return;
  putchar('\t');
  if (ioflg & PCI_IORESOURCE_PCI_EA_BEI)
      printf("[enhanced] ");
  else if ((rom & PCI_ROM_ADDRESS_MASK) && !(flg & PCI_ROM_ADDRESS_MASK))
    {
      printf("[virtual] ");
      flg = rom;
      virtual = 1;
    }
  printf("Expansion ROM at ");
  if (rom & PCI_ROM_ADDRESS_MASK)
    printf(PCIADDR_T_FMT, rom & PCI_ROM_ADDRESS_MASK);
  else if (flg & PCI_ROM_ADDRESS_MASK)
    printf("<ignored>");
  else
    printf("<unassigned>");
  if (!(flg & PCI_ROM_ADDRESS_ENABLE))
    printf(" [disabled]");
  else if (!virtual && !(cmd & PCI_COMMAND_MEMORY))
    printf(" [disabled by cmd]");
  show_size(len);
  putchar('\n');
}

static void
show_htype0(struct device *d)
{
  show_bases(d, 6);
  show_rom(d, PCI_ROM_ADDRESS);
  show_caps(d, PCI_CAPABILITY_LIST);
}

static void
show_htype1(struct device *d)
{
  u32 io_base = get_conf_byte(d, PCI_IO_BASE);
  u32 io_limit = get_conf_byte(d, PCI_IO_LIMIT);
  u32 io_type = io_base & PCI_IO_RANGE_TYPE_MASK;
  u32 mem_base = get_conf_word(d, PCI_MEMORY_BASE);
  u32 mem_limit = get_conf_word(d, PCI_MEMORY_LIMIT);
  u32 mem_type = mem_base & PCI_MEMORY_RANGE_TYPE_MASK;
  u32 pref_base = get_conf_word(d, PCI_PREF_MEMORY_BASE);
  u32 pref_limit = get_conf_word(d, PCI_PREF_MEMORY_LIMIT);
  u32 pref_type = pref_base & PCI_PREF_RANGE_TYPE_MASK;
  word sec_stat = get_conf_word(d, PCI_SEC_STATUS);
  word brc = get_conf_word(d, PCI_BRIDGE_CONTROL);

  show_bases(d, 2);
  printf("\tBus: primary=%02x, secondary=%02x, subordinate=%02x, sec-latency=%d\n",
	 get_conf_byte(d, PCI_PRIMARY_BUS),
	 get_conf_byte(d, PCI_SECONDARY_BUS),
	 get_conf_byte(d, PCI_SUBORDINATE_BUS),
	 get_conf_byte(d, PCI_SEC_LATENCY_TIMER));

  if (io_type != (io_limit & PCI_IO_RANGE_TYPE_MASK) ||
      (io_type != PCI_IO_RANGE_TYPE_16 && io_type != PCI_IO_RANGE_TYPE_32))
    printf("\t!!! Unknown I/O range types %x/%x\n", io_base, io_limit);
  else
    {
      io_base = (io_base & PCI_IO_RANGE_MASK) << 8;
      io_limit = (io_limit & PCI_IO_RANGE_MASK) << 8;
      if (io_type == PCI_IO_RANGE_TYPE_32)
	{
	  io_base |= (get_conf_word(d, PCI_IO_BASE_UPPER16) << 16);
	  io_limit |= (get_conf_word(d, PCI_IO_LIMIT_UPPER16) << 16);
	}
      show_range("\tI/O behind bridge", io_base, io_limit+0xfff, 0);
    }

  if (mem_type != (mem_limit & PCI_MEMORY_RANGE_TYPE_MASK) ||
      mem_type)
    printf("\t!!! Unknown memory range types %x/%x\n", mem_base, mem_limit);
  else
    {
      mem_base = (mem_base & PCI_MEMORY_RANGE_MASK) << 16;
      mem_limit = (mem_limit & PCI_MEMORY_RANGE_MASK) << 16;
      show_range("\tMemory behind bridge", mem_base, mem_limit + 0xfffff, 0);
    }

  if (pref_type != (pref_limit & PCI_PREF_RANGE_TYPE_MASK) ||
      (pref_type != PCI_PREF_RANGE_TYPE_32 && pref_type != PCI_PREF_RANGE_TYPE_64))
    printf("\t!!! Unknown prefetchable memory range types %x/%x\n", pref_base, pref_limit);
  else
    {
      u64 pref_base_64 = (pref_base & PCI_PREF_RANGE_MASK) << 16;
      u64 pref_limit_64 = (pref_limit & PCI_PREF_RANGE_MASK) << 16;
      if (pref_type == PCI_PREF_RANGE_TYPE_64)
	{
	  pref_base_64 |= (u64) get_conf_long(d, PCI_PREF_BASE_UPPER32) << 32;
	  pref_limit_64 |= (u64) get_conf_long(d, PCI_PREF_LIMIT_UPPER32) << 32;
	}
      show_range("\tPrefetchable memory behind bridge", pref_base_64, pref_limit_64 + 0xfffff, (pref_type == PCI_PREF_RANGE_TYPE_64));
    }

  if (verbose > 1)
    printf("\tSecondary status: 66MHz%c FastB2B%c ParErr%c DEVSEL=%s >TAbort%c <TAbort%c <MAbort%c <SERR%c <PERR%c\n",
	     FLAG(sec_stat, PCI_STATUS_66MHZ),
	     FLAG(sec_stat, PCI_STATUS_FAST_BACK),
	     FLAG(sec_stat, PCI_STATUS_PARITY),
	     ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	     ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	     ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??",
	     FLAG(sec_stat, PCI_STATUS_SIG_TARGET_ABORT),
	     FLAG(sec_stat, PCI_STATUS_REC_TARGET_ABORT),
	     FLAG(sec_stat, PCI_STATUS_REC_MASTER_ABORT),
	     FLAG(sec_stat, PCI_STATUS_SIG_SYSTEM_ERROR),
	     FLAG(sec_stat, PCI_STATUS_DETECTED_PARITY));

  show_rom(d, PCI_ROM_ADDRESS1);

  if (verbose > 1)
    {
      printf("\tBridgeCtl: Parity%c SERR%c NoISA%c VGA%c VGA16%c MAbort%c >Reset%c FastB2B%c\n",
	FLAG(brc, PCI_BRIDGE_CTL_PARITY),
	FLAG(brc, PCI_BRIDGE_CTL_SERR),
	FLAG(brc, PCI_BRIDGE_CTL_NO_ISA),
	FLAG(brc, PCI_BRIDGE_CTL_VGA),
	FLAG(brc, PCI_BRIDGE_CTL_VGA_16BIT),
	FLAG(brc, PCI_BRIDGE_CTL_MASTER_ABORT),
	FLAG(brc, PCI_BRIDGE_CTL_BUS_RESET),
	FLAG(brc, PCI_BRIDGE_CTL_FAST_BACK));
      printf("\t\tPriDiscTmr%c SecDiscTmr%c DiscTmrStat%c DiscTmrSERREn%c\n",
	FLAG(brc, PCI_BRIDGE_CTL_PRI_DISCARD_TIMER),
	FLAG(brc, PCI_BRIDGE_CTL_SEC_DISCARD_TIMER),
	FLAG(brc, PCI_BRIDGE_CTL_DISCARD_TIMER_STATUS),
	FLAG(brc, PCI_BRIDGE_CTL_DISCARD_TIMER_SERR_EN));
    }

  show_caps(d, PCI_CAPABILITY_LIST);
}

static void
show_htype2(struct device *d)
{
  int i;
  word cmd = get_conf_word(d, PCI_COMMAND);
  word brc = get_conf_word(d, PCI_CB_BRIDGE_CONTROL);
  word exca;
  int verb = verbose > 2;

  show_bases(d, 1);
  printf("\tBus: primary=%02x, secondary=%02x, subordinate=%02x, sec-latency=%d\n",
	 get_conf_byte(d, PCI_CB_PRIMARY_BUS),
	 get_conf_byte(d, PCI_CB_CARD_BUS),
	 get_conf_byte(d, PCI_CB_SUBORDINATE_BUS),
	 get_conf_byte(d, PCI_CB_LATENCY_TIMER));
  for (i=0; i<2; i++)
    {
      int p = 8*i;
      u32 base = get_conf_long(d, PCI_CB_MEMORY_BASE_0 + p);
      u32 limit = get_conf_long(d, PCI_CB_MEMORY_LIMIT_0 + p);
      limit = limit + 0xfff;
      if (base <= limit || verb)
	printf("\tMemory window %d: %08x-%08x%s%s\n", i, base, limit,
	       (cmd & PCI_COMMAND_MEMORY) ? "" : " [disabled]",
	       (brc & (PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 << i)) ? " (prefetchable)" : "");
    }
  for (i=0; i<2; i++)
    {
      int p = 8*i;
      u32 base = get_conf_long(d, PCI_CB_IO_BASE_0 + p);
      u32 limit = get_conf_long(d, PCI_CB_IO_LIMIT_0 + p);
      if (!(base & PCI_IO_RANGE_TYPE_32))
	{
	  base &= 0xffff;
	  limit &= 0xffff;
	}
      base &= PCI_CB_IO_RANGE_MASK;
      limit = (limit & PCI_CB_IO_RANGE_MASK) + 3;
      if (base <= limit || verb)
	printf("\tI/O window %d: %08x-%08x%s\n", i, base, limit,
	       (cmd & PCI_COMMAND_IO) ? "" : " [disabled]");
    }

  if (get_conf_word(d, PCI_CB_SEC_STATUS) & PCI_STATUS_SIG_SYSTEM_ERROR)
    printf("\tSecondary status: SERR\n");
  if (verbose > 1)
    printf("\tBridgeCtl: Parity%c SERR%c ISA%c VGA%c MAbort%c >Reset%c 16bInt%c PostWrite%c\n",
	   FLAG(brc, PCI_CB_BRIDGE_CTL_PARITY),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_SERR),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_ISA),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_VGA),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_MASTER_ABORT),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_CB_RESET),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_16BIT_INT),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_POST_WRITES));

  if (d->config_cached < 128)
    {
      printf("\t<access denied to the rest>\n");
      return;
    }

  exca = get_conf_word(d, PCI_CB_LEGACY_MODE_BASE);
  if (exca)
    printf("\t16-bit legacy interface ports at %04x\n", exca);
  show_caps(d, PCI_CB_CAPABILITY_LIST);
}

static void
show_verbose(struct device *d)
{
  struct pci_dev *p = d->dev;
  word status = get_conf_word(d, PCI_STATUS);
  word cmd = get_conf_word(d, PCI_COMMAND);
  word class = p->device_class;
  byte bist = get_conf_byte(d, PCI_BIST);
  byte htype = get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f;
  byte latency = get_conf_byte(d, PCI_LATENCY_TIMER);
  byte cache_line = get_conf_byte(d, PCI_CACHE_LINE_SIZE);
  byte max_lat, min_gnt;
  byte int_pin = get_conf_byte(d, PCI_INTERRUPT_PIN);
  unsigned int irq;

  show_terse(d);

  pci_fill_info(p, PCI_FILL_IRQ | PCI_FILL_BASES | PCI_FILL_ROM_BASE | PCI_FILL_SIZES |
    PCI_FILL_PHYS_SLOT | PCI_FILL_LABEL | PCI_FILL_NUMA_NODE);
  irq = p->irq;

  switch (htype)
    {
    case PCI_HEADER_TYPE_NORMAL:
      if (class == PCI_CLASS_BRIDGE_PCI)
	printf("\t!!! Invalid class %04x for header type %02x\n", class, htype);
      max_lat = get_conf_byte(d, PCI_MAX_LAT);
      min_gnt = get_conf_byte(d, PCI_MIN_GNT);
      break;
    case PCI_HEADER_TYPE_BRIDGE:
      if ((class >> 8) != PCI_BASE_CLASS_BRIDGE)
	printf("\t!!! Invalid class %04x for header type %02x\n", class, htype);
      min_gnt = max_lat = 0;
      break;
    case PCI_HEADER_TYPE_CARDBUS:
      if ((class >> 8) != PCI_BASE_CLASS_BRIDGE)
	printf("\t!!! Invalid class %04x for header type %02x\n", class, htype);
      min_gnt = max_lat = 0;
      break;
    default:
      printf("\t!!! Unknown header type %02x\n", htype);
      return;
    }

  if (p->phy_slot)
    printf("\tPhysical Slot: %s\n", p->phy_slot);

  if (verbose > 1)
    {
      printf("\tControl: I/O%c Mem%c BusMaster%c SpecCycle%c MemWINV%c VGASnoop%c ParErr%c Stepping%c SERR%c FastB2B%c DisINTx%c\n",
	     FLAG(cmd, PCI_COMMAND_IO),
	     FLAG(cmd, PCI_COMMAND_MEMORY),
	     FLAG(cmd, PCI_COMMAND_MASTER),
	     FLAG(cmd, PCI_COMMAND_SPECIAL),
	     FLAG(cmd, PCI_COMMAND_INVALIDATE),
	     FLAG(cmd, PCI_COMMAND_VGA_PALETTE),
	     FLAG(cmd, PCI_COMMAND_PARITY),
	     FLAG(cmd, PCI_COMMAND_WAIT),
	     FLAG(cmd, PCI_COMMAND_SERR),
	     FLAG(cmd, PCI_COMMAND_FAST_BACK),
	     FLAG(cmd, PCI_COMMAND_DISABLE_INTx));
      printf("\tStatus: Cap%c 66MHz%c UDF%c FastB2B%c ParErr%c DEVSEL=%s >TAbort%c <TAbort%c <MAbort%c >SERR%c <PERR%c INTx%c\n",
	     FLAG(status, PCI_STATUS_CAP_LIST),
	     FLAG(status, PCI_STATUS_66MHZ),
	     FLAG(status, PCI_STATUS_UDF),
	     FLAG(status, PCI_STATUS_FAST_BACK),
	     FLAG(status, PCI_STATUS_PARITY),
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??",
	     FLAG(status, PCI_STATUS_SIG_TARGET_ABORT),
	     FLAG(status, PCI_STATUS_REC_TARGET_ABORT),
	     FLAG(status, PCI_STATUS_REC_MASTER_ABORT),
	     FLAG(status, PCI_STATUS_SIG_SYSTEM_ERROR),
	     FLAG(status, PCI_STATUS_DETECTED_PARITY),
	     FLAG(status, PCI_STATUS_INTx));
      if (cmd & PCI_COMMAND_MASTER)
	{
	  printf("\tLatency: %d", latency);
	  if (min_gnt || max_lat)
	    {
	      printf(" (");
	      if (min_gnt)
		printf("%dns min", min_gnt*250);
	      if (min_gnt && max_lat)
		printf(", ");
	      if (max_lat)
		printf("%dns max", max_lat*250);
	      putchar(')');
	    }
	  if (cache_line)
	    printf(", Cache Line Size: %d bytes", cache_line * 4);
	  putchar('\n');
	}
      if (int_pin || irq)
	printf("\tInterrupt: pin %c routed to IRQ " PCIIRQ_FMT "\n",
	       (int_pin ? 'A' + int_pin - 1 : '?'), irq);
      if (p->numa_node != -1)
	printf("\tNUMA node: %d\n", p->numa_node);
    }
  else
    {
      printf("\tFlags: ");
      if (cmd & PCI_COMMAND_MASTER)
	printf("bus master, ");
      if (cmd & PCI_COMMAND_VGA_PALETTE)
	printf("VGA palette snoop, ");
      if (cmd & PCI_COMMAND_WAIT)
	printf("stepping, ");
      if (cmd & PCI_COMMAND_FAST_BACK)
	printf("fast Back2Back, ");
      if (status & PCI_STATUS_66MHZ)
	printf("66MHz, ");
      if (status & PCI_STATUS_UDF)
	printf("user-definable features, ");
      printf("%s devsel",
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??");
      if (cmd & PCI_COMMAND_MASTER)
	printf(", latency %d", latency);
      if (irq)
	printf(", IRQ " PCIIRQ_FMT, irq);
      if (p->numa_node != -1)
	printf(", NUMA node %d", p->numa_node);
      putchar('\n');
    }

  if (bist & PCI_BIST_CAPABLE)
    {
      if (bist & PCI_BIST_START)
	printf("\tBIST is running\n");
      else
	printf("\tBIST result: %02x\n", bist & PCI_BIST_CODE_MASK);
    }

  switch (htype)
    {
    case PCI_HEADER_TYPE_NORMAL:
      show_htype0(d);
      break;
    case PCI_HEADER_TYPE_BRIDGE:
      show_htype1(d);
      break;
    case PCI_HEADER_TYPE_CARDBUS:
      show_htype2(d);
      break;
    }
}

/*** Machine-readable dumps ***/

static void
show_hex_dump(struct device *d)
{
  unsigned int i, cnt;

  cnt = d->config_cached;
  if (opt_hex >= 3 && config_fetch(d, cnt, 256-cnt))
    {
      cnt = 256;
      if (opt_hex >= 4 && config_fetch(d, 256, 4096-256))
	cnt = 4096;
    }

  for (i=0; i<cnt; i++)
    {
      if (! (i & 15))
	printf("%02x:", i);
      printf(" %02x", get_conf_byte(d, i));
      if ((i & 15) == 15)
	putchar('\n');
    }
}

static void
fill_info_hex_dump(struct info_obj *dev_obj, struct device *d)
{
  unsigned int i, cnt;
  char buf[3] = {0};
  struct info_list *hex_dump_list = info_list_create(INFO_VAL_STRING);

  cnt = d->config_cached;
  if (opt_hex >= 3 && config_fetch(d, cnt, 256-cnt))
    {
      cnt = 256;
      if (opt_hex >= 4 && config_fetch(d, 256, 4096-256))
	cnt = 4096;
    }

  for (i=0; i<cnt; i++)
    {
      snprintf(buf, sizeof(buf), "%02x", get_conf_byte(d, i));
      info_list_add_str(hex_dump_list, buf);
    }

  info_obj_add_list(dev_obj, "hexdump", hex_dump_list);
}

static void
print_shell_escaped(char *c)
{
  printf(" \"");
  while (*c)
    {
      if (*c == '"' || *c == '\\')
	putchar('\\');
      putchar(*c++);
    }
  putchar('"');
}

static void
show_machine(struct device *d)
{
  struct pci_dev *p = d->dev;
  int c;
  word sv_id, sd_id;
  char classbuf[128], vendbuf[128], devbuf[128], svbuf[128], sdbuf[128];

  get_subid(d, &sv_id, &sd_id);

  if (verbose)
    {
      pci_fill_info(p, PCI_FILL_PHYS_SLOT | PCI_FILL_NUMA_NODE);
      printf((opt_machine >= 2) ? "Slot:\t" : "Device:\t");
      show_slot_name(d);
      putchar('\n');
      printf("Class:\t%s\n",
	     pci_lookup_name(pacc, classbuf, sizeof(classbuf), PCI_LOOKUP_CLASS, p->device_class));
      printf("Vendor:\t%s\n",
	     pci_lookup_name(pacc, vendbuf, sizeof(vendbuf), PCI_LOOKUP_VENDOR, p->vendor_id, p->device_id));
      printf("Device:\t%s\n",
	     pci_lookup_name(pacc, devbuf, sizeof(devbuf), PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id));
      if (sv_id && sv_id != 0xffff)
	{
	  printf("SVendor:\t%s\n",
		 pci_lookup_name(pacc, svbuf, sizeof(svbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR, sv_id));
	  printf("SDevice:\t%s\n",
		 pci_lookup_name(pacc, sdbuf, sizeof(sdbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id, sv_id, sd_id));
	}
      if (p->phy_slot)
	printf("PhySlot:\t%s\n", p->phy_slot);
      if (c = get_conf_byte(d, PCI_REVISION_ID))
	printf("Rev:\t%02x\n", c);
      if (c = get_conf_byte(d, PCI_CLASS_PROG))
	printf("ProgIf:\t%02x\n", c);
      if (opt_kernel)
	show_kernel_machine(d);
      if (p->numa_node != -1)
	printf("NUMANode:\t%d\n", p->numa_node);
    }
  else
    {
      show_slot_name(d);
      print_shell_escaped(pci_lookup_name(pacc, classbuf, sizeof(classbuf), PCI_LOOKUP_CLASS, p->device_class));
      print_shell_escaped(pci_lookup_name(pacc, vendbuf, sizeof(vendbuf), PCI_LOOKUP_VENDOR, p->vendor_id, p->device_id));
      print_shell_escaped(pci_lookup_name(pacc, devbuf, sizeof(devbuf), PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id));
      if (c = get_conf_byte(d, PCI_REVISION_ID))
	printf(" -r%02x", c);
      if (c = get_conf_byte(d, PCI_CLASS_PROG))
	printf(" -p%02x", c);
      if (sv_id && sv_id != 0xffff)
	{
	  print_shell_escaped(pci_lookup_name(pacc, svbuf, sizeof(svbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR, sv_id));
	  print_shell_escaped(pci_lookup_name(pacc, sdbuf, sizeof(sdbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id, sv_id, sd_id));
	}
      else
	printf(" \"\" \"\"");
      putchar('\n');
    }
}

/*** Main show function ***/

void
show_device(struct device *d)
{
  if (opt_machine)
    show_machine(d);
  else
    {
      if (verbose)
	show_verbose(d);
      else
	show_terse(d);
      if (opt_kernel || verbose)
	show_kernel(d);
    }
  if (opt_hex)
    show_hex_dump(d);
  if (verbose || opt_hex)
    putchar('\n');
}

static void
show(void)
{
  struct device *d;

  for (d=first_dev; d; d=d->next)
    show_device(d);
}

static void
fill_info_machine(struct info_obj *dev_obj, struct device *d)
{
  struct pci_dev *p = d->dev;
  int c;
  word sv_id, sd_id;
  char buf[128];

  get_subid(d, &sv_id, &sd_id);

  fill_slot_name(d, buf, sizeof(buf));
  info_obj_add_str(dev_obj, "Slot", buf);

  pci_lookup_name(pacc, buf, sizeof(buf), PCI_LOOKUP_CLASS, p->device_class);
  info_obj_add_str(dev_obj, "Class", buf);
  pci_lookup_name(pacc, buf, sizeof(buf), PCI_LOOKUP_VENDOR, p->vendor_id, p->device_id);
  info_obj_add_str(dev_obj, "Vendor", buf);
  pci_lookup_name(pacc, buf, sizeof(buf), PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id);
  info_obj_add_str(dev_obj, "Device", buf);

  if (sv_id && sv_id != 0xffff)
    {
      pci_lookup_name(pacc, buf, sizeof(buf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR, sv_id);
      info_obj_add_str(dev_obj, "SVendor", buf);
      pci_lookup_name(pacc, buf, sizeof(buf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id, sv_id, sd_id);
      info_obj_add_str(dev_obj, "SDevice", buf);
    }
  else if (!verbose)
    {
      info_obj_add_str(dev_obj, "SVendor", "");
      info_obj_add_str(dev_obj, "SDevice", "");
    }

  if (c = get_conf_byte(d, PCI_REVISION_ID))
    {
      snprintf(buf, sizeof(buf), "%02x", c);
      info_obj_add_str(dev_obj, "Rev", buf);
    }
  if (c = get_conf_byte(d, PCI_CLASS_PROG))
    {
      snprintf(buf, sizeof(buf), "%02x", c);
      info_obj_add_str(dev_obj, "ProgIf", buf);
    }

  if (opt_kernel)
     fill_info_kernel(dev_obj, d);

  if (verbose)
    {
      pci_fill_info(p, PCI_FILL_PHYS_SLOT | PCI_FILL_NUMA_NODE);
      if (p->phy_slot)
	info_obj_add_str(dev_obj, "PhySlot", p->phy_slot);
      if (p->numa_node != -1)
	{
	  snprintf(buf, sizeof(buf), "%d", p->numa_node);
	  info_obj_add_str(dev_obj, "NUMAnode", buf);
	}
    }
}

static void
fill_info_terse(struct info_obj *dev_obj, struct device *d)
{
  struct pci_dev *p = d->dev;

  fill_info_machine(dev_obj, d);

  if (verbose || opt_kernel)
    {
      word subsys_v, subsys_d;
      char ssnamebuf[256];

      if (p->label)
	info_obj_add_str(dev_obj, "DeviceName", p->label);
      info_obj_delete_pair(dev_obj, "SDevice");
      info_obj_delete_pair(dev_obj, "SVendor");
      get_subid(d, &subsys_v, &subsys_d);
      if (subsys_v && subsys_v != 0xffff)
	info_obj_add_str(dev_obj, "Subsystem",
		pci_lookup_name(pacc, ssnamebuf, sizeof(ssnamebuf),
			PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
			p->vendor_id, p->device_id, subsys_v, subsys_d));
    }
}

static void
fill_info_rom(struct info_obj *dev_obj, struct device *d, int reg)
{
  struct pci_dev *p = d->dev;
  pciaddr_t rom = p->rom_base_addr;
  pciaddr_t len = (p->known_fields & PCI_FILL_SIZES) ? p->rom_size : 0;
  pciaddr_t ioflg = (p->known_fields & PCI_FILL_IO_FLAGS) ? p->rom_flags : 0;
  u32 flg = get_conf_long(d, reg);
  word cmd = get_conf_word(d, PCI_COMMAND);
  int virtual = 0;
  char buf[64];
  struct info_obj *rom_obj;
  struct info_list *attrs_list;

  if (!rom && !flg && !len)
    return;

  rom_obj = info_obj_create_in_obj(dev_obj, "ROM");
  attrs_list = info_list_create(INFO_VAL_STRING);
  info_obj_add_list(rom_obj, "attrs", attrs_list);

  if (ioflg & PCI_IORESOURCE_PCI_EA_BEI)
      info_list_add_str(attrs_list, "[enhanced]");
  else if ((rom & PCI_ROM_ADDRESS_MASK) && !(flg & PCI_ROM_ADDRESS_MASK))
    {
      info_list_add_str(attrs_list, "[virtual]");
      flg = rom;
      virtual = 1;
    }

  if (rom & PCI_ROM_ADDRESS_MASK)
    info_obj_add_fmt_buf_str(rom_obj, "at", buf, sizeof(buf), PCIADDR_T_FMT, rom & PCI_ROM_ADDRESS_MASK);
  else if (flg & PCI_ROM_ADDRESS_MASK)
    info_list_add_str(attrs_list, "<ignored>");
  else
    info_list_add_str(attrs_list, "<unassigned>");

  if (!(flg & PCI_ROM_ADDRESS_ENABLE))
    info_list_add_str(attrs_list, "[disabled]");
  else if (!virtual && !(cmd & PCI_COMMAND_MEMORY))
    info_list_add_str(attrs_list, "[disabled by cmd]");

  fill_size(buf, sizeof(buf), len);
  info_obj_add_str(rom_obj, "size", buf);
}

static void
fill_info_bases(struct info_obj *dev_obj, struct device *d, int cnt)
{
  struct pci_dev *p = d->dev;
  word cmd = get_conf_word(d, PCI_COMMAND);
  int i;
  int virtual = 0;
  char buf[64];
  struct info_obj *bases_obj = info_obj_create_in_obj(dev_obj, "bases");
  struct info_list *regions_list = info_list_create(INFO_VAL_OBJECT);

  info_obj_add_list(bases_obj, "regions", regions_list);

  for (i=0; i<cnt; i++)
    {
      struct info_obj *region_obj;
      struct info_list *attrs_list;

      pciaddr_t pos = p->base_addr[i];
      pciaddr_t len = (p->known_fields & PCI_FILL_SIZES) ? p->size[i] : 0;
      pciaddr_t ioflg = (p->known_fields & PCI_FILL_IO_FLAGS) ? p->flags[i] : 0;
      u32 flg = get_conf_long(d, PCI_BASE_ADDRESS_0 + 4*i);
      if (flg == 0xffffffff)
	flg = 0;
      if (!pos && !flg && !len)
	continue;

      region_obj = info_obj_create();
      info_list_add_obj(regions_list, region_obj);
      attrs_list = info_list_create(INFO_VAL_STRING);
      info_obj_add_list(region_obj, "attrs", attrs_list);

      if (ioflg & PCI_IORESOURCE_PCI_EA_BEI)
	  info_list_add_str(attrs_list, "[enhanced]");
      else if (pos && !flg)	/* Reported by the OS, but not by the device */
	{
	  info_list_add_str(attrs_list, "[virtual]");
	  flg = pos;
	  virtual = 1;
	}
      if (flg & PCI_BASE_ADDRESS_SPACE_IO)
	{
	  pciaddr_t a = pos & PCI_BASE_ADDRESS_IO_MASK;
	  if (a || (cmd & PCI_COMMAND_IO))
	    info_obj_add_fmt_buf_str(region_obj, "io-ports-at", buf, sizeof(buf), PCIADDR_PORT_FMT, a);
	  else if (flg & PCI_BASE_ADDRESS_IO_MASK)
	    info_list_add_str(attrs_list, "<ignored>");
	  else
	    info_list_add_str(attrs_list, "<unassigned>");
	  if (!virtual && !(cmd & PCI_COMMAND_IO))
	    info_list_add_str(attrs_list, "[disabled]");
	}
      else
	{
	  int t = flg & PCI_BASE_ADDRESS_MEM_TYPE_MASK;
	  pciaddr_t a = pos & PCI_ADDR_MEM_MASK;
	  int done = 0;
	  u32 z = 0;

	  if (t == PCI_BASE_ADDRESS_MEM_TYPE_64)
	    {
	      if (i >= cnt - 1)
		{
		  info_list_add_str(attrs_list, "<invalid-64bit-slot>");
		  done = 1;
		}
	      else
		{
		  i++;
		  z = get_conf_long(d, PCI_BASE_ADDRESS_0 + 4*i);
		}
	    }
	  if (!done)
	    {
	      if (a)
		info_obj_add_fmt_buf_str(region_obj, "memory-at", buf, sizeof(buf), PCIADDR_T_FMT, a);
	      else
		{
		  if ((flg & PCI_BASE_ADDRESS_MEM_MASK) || z)
		    info_list_add_str(attrs_list, "<ignored>");
		  else
		    info_list_add_str(attrs_list, "<unassigned>");
		}
	    }
	  info_list_add_str(attrs_list,
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_32) ? "32-bit" :
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_64) ? "64-bit" :
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_1M) ? "low-1M" : "type 3");
	  info_list_add_str(attrs_list,
		 (flg & PCI_BASE_ADDRESS_MEM_PREFETCH) ? "prefetchable" : "non-prefetchable");
	  if (!virtual && !(cmd & PCI_COMMAND_MEMORY))
	    info_list_add_str(attrs_list, "[disabled]");
	}
      fill_size(buf, sizeof(buf), len);
      info_obj_add_str(region_obj, "size", buf);
    }
}

static void
fill_info_htype0(struct info_obj *dev_obj, struct device *d)
{
  struct info_obj *htype0_obj = info_obj_create_in_obj(dev_obj, "htype0");

  fill_info_bases(htype0_obj, d, 6);
  fill_info_rom(htype0_obj, d, PCI_ROM_ADDRESS);
}

static void
fill_info_htype1(struct info_obj *dev_obj, struct device *d)
{
  u32 io_base = get_conf_byte(d, PCI_IO_BASE);
  u32 io_limit = get_conf_byte(d, PCI_IO_LIMIT);
  u32 io_type = io_base & PCI_IO_RANGE_TYPE_MASK;
  u32 mem_base = get_conf_word(d, PCI_MEMORY_BASE);
  u32 mem_limit = get_conf_word(d, PCI_MEMORY_LIMIT);
  u32 mem_type = mem_base & PCI_MEMORY_RANGE_TYPE_MASK;
  u32 pref_base = get_conf_word(d, PCI_PREF_MEMORY_BASE);
  u32 pref_limit = get_conf_word(d, PCI_PREF_MEMORY_LIMIT);
  u32 pref_type = pref_base & PCI_PREF_RANGE_TYPE_MASK;
  word sec_stat = get_conf_word(d, PCI_SEC_STATUS);
  word brc = get_conf_word(d, PCI_BRIDGE_CONTROL);
  struct info_obj *htype1_obj = info_obj_create_in_obj(dev_obj, "htype1");
  struct info_obj *bus_obj;
  char buf[64];

  fill_info_bases(htype1_obj, d, 2);

  bus_obj = info_obj_create_in_obj(htype1_obj, "Bus");
  info_obj_add_fmt_buf_str(bus_obj, "primary", buf, sizeof(buf), "%02x", get_conf_byte(d, PCI_PRIMARY_BUS));
  info_obj_add_fmt_buf_str(bus_obj, "secondary", buf, sizeof(buf), "%02x", get_conf_byte(d, PCI_SECONDARY_BUS));
  info_obj_add_fmt_buf_str(bus_obj, "subordinate", buf, sizeof(buf), "%02x", get_conf_byte(d, PCI_SUBORDINATE_BUS));
  info_obj_add_fmt_buf_str(bus_obj, "sec-latency", buf, sizeof(buf), "%d", get_conf_byte(d, PCI_SEC_LATENCY_TIMER));

  if (io_type != (io_limit & PCI_IO_RANGE_TYPE_MASK) ||
      (io_type != PCI_IO_RANGE_TYPE_16 && io_type != PCI_IO_RANGE_TYPE_32))
    fprintf(stderr, "\t!!! Unknown I/O range types %x/%x\n", io_base, io_limit);
  else
    {
      io_base = (io_base & PCI_IO_RANGE_MASK) << 8;
      io_limit = (io_limit & PCI_IO_RANGE_MASK) << 8;
      if (io_type == PCI_IO_RANGE_TYPE_32)
	{
	  io_base |= (get_conf_word(d, PCI_IO_BASE_UPPER16) << 16);
	  io_limit |= (get_conf_word(d, PCI_IO_LIMIT_UPPER16) << 16);
	}
      fill_range(buf, sizeof(buf), io_base, io_limit + 0xfff, 0);
      info_obj_add_str(htype1_obj, "io-behind-bridge", buf);
    }

  if (mem_type != (mem_limit & PCI_MEMORY_RANGE_TYPE_MASK) ||
      mem_type)
    fprintf(stderr, "\t!!! Unknown memory range types %x/%x\n", mem_base, mem_limit);
  else
    {
      mem_base = (mem_base & PCI_MEMORY_RANGE_MASK) << 16;
      mem_limit = (mem_limit & PCI_MEMORY_RANGE_MASK) << 16;
      fill_range(buf, sizeof(buf), mem_base, mem_limit + 0xfffff, 0);
      info_obj_add_str(htype1_obj, "memory-behind-bridge", buf);
    }

  if (pref_type != (pref_limit & PCI_PREF_RANGE_TYPE_MASK) ||
      (pref_type != PCI_PREF_RANGE_TYPE_32 && pref_type != PCI_PREF_RANGE_TYPE_64))
    fprintf(stderr, "\t!!! Unknown prefetchable memory range types %x/%x\n", pref_base, pref_limit);
  else
    {
      u64 pref_base_64 = (pref_base & PCI_PREF_RANGE_MASK) << 16;
      u64 pref_limit_64 = (pref_limit & PCI_PREF_RANGE_MASK) << 16;
      if (pref_type == PCI_PREF_RANGE_TYPE_64)
	{
	  pref_base_64 |= (u64) get_conf_long(d, PCI_PREF_BASE_UPPER32) << 32;
	  pref_limit_64 |= (u64) get_conf_long(d, PCI_PREF_LIMIT_UPPER32) << 32;
	}
      fill_range(buf, sizeof(buf), pref_base_64, pref_limit_64 + 0xfffff, (pref_type == PCI_PREF_RANGE_TYPE_64));
      info_obj_add_str(htype1_obj, "prefetchable-memory-behind-bridge", buf);
    }

  if (verbose > 1)
    {
      struct info_obj *sec_status_obj = info_obj_create();

      sec_status_obj = info_obj_create_in_obj(htype1_obj, "SecondaryStatus");
      info_obj_add_flag(sec_status_obj, "66MHz", FLAG(sec_stat, PCI_STATUS_66MHZ));
      info_obj_add_flag(sec_status_obj, "FastB2B", FLAG(sec_stat, PCI_STATUS_FAST_BACK));
      info_obj_add_flag(sec_status_obj, "ParErr", FLAG(sec_stat, PCI_STATUS_PARITY));
      info_obj_add_str(sec_status_obj, "DEVSEL=", ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	      ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	      ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??");
      info_obj_add_flag(sec_status_obj, ">TAbort", FLAG(sec_stat, PCI_STATUS_SIG_TARGET_ABORT));
      info_obj_add_flag(sec_status_obj, "<TAbort", FLAG(sec_stat, PCI_STATUS_REC_TARGET_ABORT));
      info_obj_add_flag(sec_status_obj, "<MAbort", FLAG(sec_stat, PCI_STATUS_REC_MASTER_ABORT));
      info_obj_add_flag(sec_status_obj, "<SERR", FLAG(sec_stat, PCI_STATUS_SIG_SYSTEM_ERROR));
      info_obj_add_flag(sec_status_obj, "<PERR", FLAG(sec_stat, PCI_STATUS_DETECTED_PARITY));
    }

  fill_info_rom(htype1_obj, d, PCI_ROM_ADDRESS1);

  if (verbose > 1)
    {
      struct info_obj *bridgectl_obj;

      bridgectl_obj = info_obj_create_in_obj(htype1_obj, "BridgeCtl");
      info_obj_add_flag(bridgectl_obj, "Parity", FLAG(brc, PCI_BRIDGE_CTL_PARITY));
      info_obj_add_flag(bridgectl_obj, "SERR", FLAG(brc, PCI_BRIDGE_CTL_SERR));
      info_obj_add_flag(bridgectl_obj, "NoISA", FLAG(brc, PCI_BRIDGE_CTL_NO_ISA));
      info_obj_add_flag(bridgectl_obj, "VGA", FLAG(brc, PCI_BRIDGE_CTL_VGA));
      info_obj_add_flag(bridgectl_obj, "VGA16", FLAG(brc, PCI_BRIDGE_CTL_VGA_16BIT));
      info_obj_add_flag(bridgectl_obj, "MAbort", FLAG(brc, PCI_BRIDGE_CTL_MASTER_ABORT));
      info_obj_add_flag(bridgectl_obj, ">Reset", FLAG(brc, PCI_BRIDGE_CTL_BUS_RESET));
      info_obj_add_flag(bridgectl_obj, "FastB2B", FLAG(brc, PCI_BRIDGE_CTL_FAST_BACK));
      info_obj_add_flag(bridgectl_obj, "PriDiscTmr", FLAG(brc, PCI_BRIDGE_CTL_PRI_DISCARD_TIMER));
      info_obj_add_flag(bridgectl_obj, "SecDiscTmr", FLAG(brc, PCI_BRIDGE_CTL_SEC_DISCARD_TIMER));
      info_obj_add_flag(bridgectl_obj, "DiscTmrStat", FLAG(brc, PCI_BRIDGE_CTL_DISCARD_TIMER_STATUS));
      info_obj_add_flag(bridgectl_obj, "DiscTmrSERREn", FLAG(brc, PCI_BRIDGE_CTL_DISCARD_TIMER_SERR_EN));
    }
}

static void
fill_info_htype2(struct info_obj *dev_obj, struct device *d)
{
  int i;
  word cmd = get_conf_word(d, PCI_COMMAND);
  word brc = get_conf_word(d, PCI_CB_BRIDGE_CONTROL);
  word exca;
  int verb = verbose > 2;
  struct info_obj *htype2_obj = info_obj_create_in_obj(dev_obj, "htype2");
  struct info_obj *bus_obj;
  char buf[64];

  fill_info_bases(htype2_obj, d, 1);

  bus_obj = info_obj_create_in_obj(htype2_obj, "Bus");
  info_obj_add_fmt_buf_str(bus_obj, "primary", buf, sizeof(buf), "%02x", get_conf_byte(d, PCI_CB_PRIMARY_BUS));
  info_obj_add_fmt_buf_str(bus_obj, "secondary", buf, sizeof(buf), "%02x", get_conf_byte(d, PCI_CB_CARD_BUS));
  info_obj_add_fmt_buf_str(bus_obj, "subordinate", buf, sizeof(buf), "%02x", get_conf_byte(d, PCI_CB_SUBORDINATE_BUS));
  info_obj_add_fmt_buf_str(bus_obj, "sec-latency", buf, sizeof(buf), "%d", get_conf_byte(d, PCI_CB_LATENCY_TIMER));

  for (i=0; i<2; i++)
    {
      int p = 8*i;
      struct info_obj *mem_win_obj;

      u32 base = get_conf_long(d, PCI_CB_MEMORY_BASE_0 + p);
      u32 limit = get_conf_long(d, PCI_CB_MEMORY_LIMIT_0 + p);
      limit = limit + 0xfff;
      if (base <= limit || verb)
	{
	  snprintf(buf, sizeof(buf), "memory-window-%d", i);
	  mem_win_obj = info_obj_create_in_obj(htype2_obj, buf);
	  info_obj_add_fmt_buf_str(mem_win_obj, "base", buf, sizeof(buf), "%08x", base);
	  info_obj_add_fmt_buf_str(mem_win_obj, "limit", buf, sizeof(buf), "%08x", limit);
	  info_obj_add_flag(mem_win_obj, "disabled", (cmd & PCI_COMMAND_MEMORY) ? '-' : '+');
	  info_obj_add_flag(mem_win_obj, "prefetchable", (brc & (PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 << i)) ? '-' : '+');
	}
    }
  for (i=0; i<2; i++)
    {
      int p = 8*i;
      struct info_obj *io_win_obj;

      u32 base = get_conf_long(d, PCI_CB_IO_BASE_0 + p);
      u32 limit = get_conf_long(d, PCI_CB_IO_LIMIT_0 + p);
      if (!(base & PCI_IO_RANGE_TYPE_32))
	{
	  base &= 0xffff;
	  limit &= 0xffff;
	}
      base &= PCI_CB_IO_RANGE_MASK;
      limit = (limit & PCI_CB_IO_RANGE_MASK) + 3;
      if (base <= limit || verb)
	{
	  snprintf(buf, sizeof(buf), "io-window-%d", i);
	  io_win_obj = info_obj_create_in_obj(htype2_obj, buf);
	  info_obj_add_fmt_buf_str(io_win_obj, "base", buf, sizeof(buf), "%08x", base);
	  info_obj_add_fmt_buf_str(io_win_obj, "limit", buf, sizeof(buf), "%08x", limit);
	  info_obj_add_flag(io_win_obj, "disabled", (cmd & PCI_COMMAND_IO) ? '-' : '+');
	}
    }

  if (get_conf_word(d, PCI_CB_SEC_STATUS) & PCI_STATUS_SIG_SYSTEM_ERROR)
    info_obj_add_str(htype2_obj, "SecondaryStatus", "SERR");
  if (verbose > 1)
    {
      struct info_obj *bridgectl_obj;

      bridgectl_obj = info_obj_create_in_obj(htype2_obj, "BridgeCtl");
      info_obj_add_flag(bridgectl_obj, "Parity", FLAG(brc, PCI_CB_BRIDGE_CTL_PARITY));
      info_obj_add_flag(bridgectl_obj, "SERR", FLAG(brc, PCI_CB_BRIDGE_CTL_SERR));
      info_obj_add_flag(bridgectl_obj, "ISA", FLAG(brc, PCI_CB_BRIDGE_CTL_ISA));
      info_obj_add_flag(bridgectl_obj, "VGA", FLAG(brc, PCI_CB_BRIDGE_CTL_VGA));
      info_obj_add_flag(bridgectl_obj, "MAbort", FLAG(brc, PCI_CB_BRIDGE_CTL_MASTER_ABORT));
      info_obj_add_flag(bridgectl_obj, ">Reset", FLAG(brc, PCI_CB_BRIDGE_CTL_CB_RESET));
      info_obj_add_flag(bridgectl_obj, "16bInt", FLAG(brc, PCI_CB_BRIDGE_CTL_16BIT_INT));
      info_obj_add_flag(bridgectl_obj, "PostWrite", FLAG(brc, PCI_CB_BRIDGE_CTL_POST_WRITES));
    }

  if (d->config_cached < 128)
    return;

  exca = get_conf_word(d, PCI_CB_LEGACY_MODE_BASE);
  if (exca)
    info_obj_add_fmt_buf_str(htype2_obj, "exca", buf, sizeof(buf), "%04x", exca);
}

static void
fill_info_verbose(struct info_obj *dev_obj, struct device *d)
{
  struct pci_dev *p = d->dev;
  word status = get_conf_word(d, PCI_STATUS);
  word cmd = get_conf_word(d, PCI_COMMAND);
  word class = p->device_class;
  byte bist = get_conf_byte(d, PCI_BIST);
  byte htype = get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f;
  byte latency = get_conf_byte(d, PCI_LATENCY_TIMER);
  byte cache_line = get_conf_byte(d, PCI_CACHE_LINE_SIZE);
  byte max_lat, min_gnt;
  byte int_pin = get_conf_byte(d, PCI_INTERRUPT_PIN);
  unsigned int irq;

  fill_info_terse(dev_obj, d);
  pci_fill_info(p, PCI_FILL_IRQ | PCI_FILL_BASES | PCI_FILL_ROM_BASE | PCI_FILL_SIZES |
    PCI_FILL_PHYS_SLOT | PCI_FILL_LABEL | PCI_FILL_NUMA_NODE);
  irq = p->irq;

  switch (htype)
    {
    case PCI_HEADER_TYPE_NORMAL:
      if (class == PCI_CLASS_BRIDGE_PCI)
	fprintf(stderr, "\t!!! Invalid class %04x for header type %02x\n", class, htype);
      max_lat = get_conf_byte(d, PCI_MAX_LAT);
      min_gnt = get_conf_byte(d, PCI_MIN_GNT);
      break;
    case PCI_HEADER_TYPE_BRIDGE:
      if ((class >> 8) != PCI_BASE_CLASS_BRIDGE)
	fprintf(stderr, "\t!!! Invalid class %04x for header type %02x\n", class, htype);
      min_gnt = max_lat = 0;
      break;
    case PCI_HEADER_TYPE_CARDBUS:
      if ((class >> 8) != PCI_BASE_CLASS_BRIDGE)
	fprintf(stderr, "\t!!! Invalid class %04x for header type %02x\n", class, htype);
      min_gnt = max_lat = 0;
      break;
    default:
      fprintf(stderr, "\t!!! Unknown header type %02x\n", htype);
      return;
    }

  if (p->phy_slot)
    info_obj_add_str(dev_obj, "PhySlot", p->phy_slot);

  if (verbose > 1)
    {
      struct info_obj *control_obj;
      struct info_obj *status_obj;

      control_obj = info_obj_create_in_obj(dev_obj, "Control");
      info_obj_add_flag(control_obj, "I/O", FLAG(cmd, PCI_COMMAND_IO));
      info_obj_add_flag(control_obj, "Mem", FLAG(cmd, PCI_COMMAND_MEMORY));
      info_obj_add_flag(control_obj, "BusMaster", FLAG(cmd, PCI_COMMAND_MASTER));
      info_obj_add_flag(control_obj, "SpecCycle", FLAG(cmd, PCI_COMMAND_SPECIAL));
      info_obj_add_flag(control_obj, "MemWINV", FLAG(cmd, PCI_COMMAND_INVALIDATE));
      info_obj_add_flag(control_obj, "VGASnoop", FLAG(cmd, PCI_COMMAND_VGA_PALETTE));
      info_obj_add_flag(control_obj, "ParErr", FLAG(cmd, PCI_COMMAND_PARITY));
      info_obj_add_flag(control_obj, "Stepping", FLAG(cmd, PCI_COMMAND_WAIT));
      info_obj_add_flag(control_obj, "SERR", FLAG(cmd, PCI_COMMAND_SERR));
      info_obj_add_flag(control_obj, "FastB2B", FLAG(cmd, PCI_COMMAND_FAST_BACK));
      info_obj_add_flag(control_obj, "DisINTx", FLAG(cmd, PCI_COMMAND_DISABLE_INTx));

      status_obj = info_obj_create_in_obj(dev_obj, "Status");
      info_obj_add_flag(status_obj, "Cap", FLAG(status, PCI_STATUS_CAP_LIST));
      info_obj_add_flag(status_obj, "66MHz", FLAG(status, PCI_STATUS_66MHZ));
      info_obj_add_flag(status_obj, "UDF", FLAG(status, PCI_STATUS_UDF));
      info_obj_add_flag(status_obj, "FastB2B", FLAG(status, PCI_STATUS_FAST_BACK));
      info_obj_add_flag(status_obj, "ParErr", FLAG(status, PCI_STATUS_PARITY));
      info_obj_add_str(status_obj, "DEVSEL=",
	      ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	      ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	      ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??");
      info_obj_add_flag(status_obj, ">TAbort", FLAG(status, PCI_STATUS_SIG_TARGET_ABORT));
      info_obj_add_flag(status_obj, "<TAbort", FLAG(status, PCI_STATUS_REC_TARGET_ABORT));
      info_obj_add_flag(status_obj, "<MAbort", FLAG(status, PCI_STATUS_REC_MASTER_ABORT));
      info_obj_add_flag(status_obj, ">SERR", FLAG(status, PCI_STATUS_SIG_SYSTEM_ERROR));
      info_obj_add_flag(status_obj, "<PERR", FLAG(status, PCI_STATUS_DETECTED_PARITY));
      info_obj_add_flag(status_obj, "INTx", FLAG(status, PCI_STATUS_INTx));

      if (cmd & PCI_COMMAND_MASTER)
	{
	  info_obj_add_fmt_str(dev_obj, "Latency", 16, "%d", latency);
	  if (min_gnt)
	    info_obj_add_fmt_str(dev_obj, "min-gnt", 16, "%d", min_gnt*250);
	  if (max_lat)
	    info_obj_add_fmt_str(dev_obj, "max-lat", 16, "%d", max_lat*250);
	  if (cache_line)
	    info_obj_add_fmt_str(dev_obj, "CacheLineSize", 16, "%d", cache_line * 4);
	}
      if (int_pin || irq)
	{
	  info_obj_add_fmt_str(dev_obj, "int-pin", 2, "%c", (int_pin ? 'A' + int_pin - 1 : '?'));
	  info_obj_add_fmt_str(dev_obj, "IRQ", 16, PCIIRQ_FMT, irq);
	}
    }
  else
    {
      struct info_list *flags_list =  info_list_create(INFO_VAL_STRING);

      info_obj_add_list(dev_obj, "Flags", flags_list);
      if (cmd & PCI_COMMAND_MASTER)
	info_list_add_str(flags_list, "bus master");
      if (cmd & PCI_COMMAND_VGA_PALETTE)
	info_list_add_str(flags_list, "VGA palette snoop");
      if (cmd & PCI_COMMAND_WAIT)
	info_list_add_str(flags_list, "stepping");
      if (cmd & PCI_COMMAND_FAST_BACK)
	info_list_add_str(flags_list, "fast Back2Back");
      if (status & PCI_STATUS_66MHZ)
	info_list_add_str(flags_list, "66MHz");
      if (status & PCI_STATUS_UDF)
	info_list_add_str(flags_list, "user-definable features");

      info_obj_add_str(dev_obj, "devsel",
	      ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	      ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	      ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??");
      if (cmd & PCI_COMMAND_MASTER)
	info_obj_add_fmt_str(dev_obj, "Latency", 16, "%d", latency);
      if (irq)
	info_obj_add_fmt_str(dev_obj, "IRQ", 16, PCIIRQ_FMT, irq);
    }

  if (bist & PCI_BIST_CAPABLE)
    {
      if (bist & PCI_BIST_START)
	info_obj_add_str(dev_obj, "BIST", "running");
      else
	info_obj_add_fmt_str(dev_obj, "BIST", 3, "%02x", bist & PCI_BIST_CODE_MASK);
    }

  switch (htype)
    {
    case PCI_HEADER_TYPE_NORMAL:
      fill_info_htype0(dev_obj, d);
      break;
    case PCI_HEADER_TYPE_BRIDGE:
      fill_info_htype1(dev_obj, d);
      break;
    case PCI_HEADER_TYPE_CARDBUS:
      fill_info_htype2(dev_obj, d);
      break;
    }
}

static void
fill_info_device(struct info_obj *dev_obj, struct device *d)
{
  if (opt_machine)
    fill_info_machine(dev_obj, d);
  else
    {
      if (verbose)
	fill_info_verbose(dev_obj, d);
      else
	fill_info_terse(dev_obj, d);
      if (!opt_kernel && verbose)
	fill_info_kernel(dev_obj, d);
    }
  if (opt_hex)
    fill_info_hex_dump(dev_obj, d);
}

static void
fill_info(struct info_obj *root)
{
  struct device *d;
  struct info_list *dev_list = info_list_create(INFO_VAL_OBJECT);

  for (d=first_dev; d; d=d->next)
    {
      struct info_obj *dev_obj = info_obj_create();
      fill_info_device(dev_obj, d);
      info_list_add_obj(dev_list, dev_obj);
    }

  info_obj_add_list(root, "pcidevices", dev_list);
}

static void
show_json(void)
{
  struct info_obj *root = info_obj_create();

  fill_info(root);
  info_obj_print_json(root, 0);
  info_obj_delete(root);
}

/* Main */

int
main(int argc, char **argv)
{
  int i;
  char *msg;

  if (argc == 2 && !strcmp(argv[1], "--version"))
    {
      puts("lspci version " PCIUTILS_VERSION);
      return 0;
    }

  pacc = pci_alloc();
  pacc->error = die;
  pci_filter_init(pacc, &filter);

  while ((i = getopt(argc, argv, options)) != -1)
    switch (i)
      {
      case 'n':
	pacc->numeric_ids++;
	break;
      case 'v':
	verbose++;
	break;
      case 'b':
	pacc->buscentric = 1;
	break;
      case 's':
	if (msg = pci_filter_parse_slot(&filter, optarg))
	  die("-s: %s", msg);
	break;
      case 'd':
	if (msg = pci_filter_parse_id(&filter, optarg))
	  die("-d: %s", msg);
	break;
      case 'x':
	opt_hex++;
	break;
      case 't':
	opt_tree++;
	break;
      case 'i':
        pci_set_name_list_path(pacc, optarg, 0);
	break;
      case 'm':
	opt_machine++;
	break;
      case 'p':
	opt_pcimap = optarg;
	break;
#ifdef PCI_OS_LINUX
      case 'k':
	opt_kernel++;
	break;
#endif
      case 'M':
	opt_map_mode++;
	break;
      case 'D':
	opt_domains = 2;
	break;
      case 'J':
	opt_json = 1;
	break;
#ifdef PCI_USE_DNS
      case 'q':
	opt_query_dns++;
	break;
      case 'Q':
	opt_query_all = 1;
	break;
#else
      case 'q':
      case 'Q':
	die("DNS queries are not available in this version");
#endif
      default:
	if (parse_generic_option(i, pacc, optarg))
	  break;
      bad:
	fprintf(stderr, help_msg, pacc->id_file_name);
	return 1;
      }
  if (optind < argc)
    goto bad;

  if (opt_query_dns)
    {
      pacc->id_lookup_mode |= PCI_LOOKUP_NETWORK;
      if (opt_query_dns > 1)
	pacc->id_lookup_mode |= PCI_LOOKUP_REFRESH_CACHE;
    }
  if (opt_query_all)
    pacc->id_lookup_mode |= PCI_LOOKUP_NETWORK | PCI_LOOKUP_SKIP_LOCAL;

  pci_init(pacc);
  if (opt_map_mode)
    map_the_bus();
  else
    {
      scan_devices();
      sort_them();
      if (opt_tree)
	show_forest();
      else if (opt_json)
	show_json();
      else
	show();
    }
  show_kernel_cleanup();
  pci_cleanup(pacc);

  return (seen_errors ? 2 : 0);
}
