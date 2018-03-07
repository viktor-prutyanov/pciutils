/*
 *	The PCI Utilities -- Show Capabilities
 *
 *	Copyright (c) 1997--2018 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <string.h>

#include "lspci.h"

static void
cap_pm(struct device *d, int where, int cap)
{
  int t, b;
  static int pm_aux_current[8] = { 0, 55, 100, 160, 220, 270, 320, 375 };

  printf("Power Management version %d\n", cap & PCI_PM_CAP_VER_MASK);
  if (verbose < 2)
    return;
  printf("\t\tFlags: PMEClk%c DSI%c D1%c D2%c AuxCurrent=%dmA PME(D0%c,D1%c,D2%c,D3hot%c,D3cold%c)\n",
	 FLAG(cap, PCI_PM_CAP_PME_CLOCK),
	 FLAG(cap, PCI_PM_CAP_DSI),
	 FLAG(cap, PCI_PM_CAP_D1),
	 FLAG(cap, PCI_PM_CAP_D2),
	 pm_aux_current[(cap & PCI_PM_CAP_AUX_C_MASK) >> 6],
	 FLAG(cap, PCI_PM_CAP_PME_D0),
	 FLAG(cap, PCI_PM_CAP_PME_D1),
	 FLAG(cap, PCI_PM_CAP_PME_D2),
	 FLAG(cap, PCI_PM_CAP_PME_D3_HOT),
	 FLAG(cap, PCI_PM_CAP_PME_D3_COLD));
  if (!config_fetch(d, where + PCI_PM_CTRL, PCI_PM_SIZEOF - PCI_PM_CTRL))
    return;
  t = get_conf_word(d, where + PCI_PM_CTRL);
  printf("\t\tStatus: D%d NoSoftRst%c PME-Enable%c DSel=%d DScale=%d PME%c\n",
	 t & PCI_PM_CTRL_STATE_MASK,
	 FLAG(t, PCI_PM_CTRL_NO_SOFT_RST),
	 FLAG(t, PCI_PM_CTRL_PME_ENABLE),
	 (t & PCI_PM_CTRL_DATA_SEL_MASK) >> 9,
	 (t & PCI_PM_CTRL_DATA_SCALE_MASK) >> 13,
	 FLAG(t, PCI_PM_CTRL_PME_STATUS));
  b = get_conf_byte(d, where + PCI_PM_PPB_EXTENSIONS);
  if (b)
    printf("\t\tBridge: PM%c B3%c\n",
	   FLAG(t, PCI_PM_BPCC_ENABLE),
	   FLAG(~t, PCI_PM_PPB_B2_B3));
}

static void
fill_info_cap_pm(struct info_obj *caps_obj, struct device *d, int where, int cap)
{
  int t, b;
  static int pm_aux_current[8] = { 0, 55, 100, 160, 220, 270, 320, 375 };
  struct info_obj *pm_obj, *flags_obj, *status_obj;
  char buf[64];

  pm_obj = info_obj_create_in_obj(caps_obj, "Power-Management");
  info_obj_add_fmt_buf_str(pm_obj, "version", buf, sizeof(buf), "%d", cap & PCI_PM_CAP_VER_MASK);
  if (verbose < 2)
    return;
  flags_obj = info_obj_create_in_obj(pm_obj, "Flags");
  info_obj_add_flag(flags_obj, "PMEClk", FLAG(cap, PCI_PM_CAP_PME_CLOCK));
  info_obj_add_flag(flags_obj, "DSI", FLAG(cap, PCI_PM_CAP_DSI));
  info_obj_add_flag(flags_obj, "D1", FLAG(cap, PCI_PM_CAP_D1));
  info_obj_add_flag(flags_obj, "D2", FLAG(cap, PCI_PM_CAP_D2));
  info_obj_add_fmt_buf_str(flags_obj, "AuxCurrent", buf, sizeof(buf), "%dmA", pm_aux_current[(cap & PCI_PM_CAP_AUX_C_MASK) >> 6]);
  info_obj_add_flag(flags_obj, "PME-D0", FLAG(cap, PCI_PM_CAP_PME_D0));
  info_obj_add_flag(flags_obj, "PME-D1", FLAG(cap, PCI_PM_CAP_PME_D1));
  info_obj_add_flag(flags_obj, "PME-D2", FLAG(cap, PCI_PM_CAP_PME_D2));
  info_obj_add_flag(flags_obj, "PME-D3hot", FLAG(cap, PCI_PM_CAP_PME_D3_HOT));
  info_obj_add_flag(flags_obj, "PME-D3cold", FLAG(cap, PCI_PM_CAP_PME_D3_COLD));
  if (!config_fetch(d, where + PCI_PM_CTRL, PCI_PM_SIZEOF - PCI_PM_CTRL))
    return;
  t = get_conf_word(d, where + PCI_PM_CTRL);
  status_obj = info_obj_create_in_obj(pm_obj, "Status");
  info_obj_add_fmt_buf_str(status_obj, "D", buf, sizeof(buf), "%d", t & PCI_PM_CTRL_STATE_MASK);
  info_obj_add_flag(status_obj, "NoSoftRst", FLAG(t, PCI_PM_CTRL_NO_SOFT_RST));
  info_obj_add_flag(status_obj, "PME-Enable", FLAG(t, PCI_PM_CTRL_PME_ENABLE));
  info_obj_add_fmt_buf_str(status_obj, "DSel", buf, sizeof(buf), "%d", (t & PCI_PM_CTRL_DATA_SEL_MASK) >> 9);
  info_obj_add_fmt_buf_str(status_obj, "DScale", buf, sizeof(buf), "%d", (t & PCI_PM_CTRL_DATA_SCALE_MASK) >> 13);
  info_obj_add_flag(status_obj, "PME", FLAG(t, PCI_PM_CTRL_PME_STATUS));
  b = get_conf_byte(d, where + PCI_PM_PPB_EXTENSIONS);
  if (b)
    {
      struct info_obj *bridge_obj = info_obj_create_in_obj(pm_obj, "Bridge");
      info_obj_add_flag(bridge_obj, "PM", FLAG(t, PCI_PM_BPCC_ENABLE));
      info_obj_add_flag(bridge_obj, "B3", FLAG(~t, PCI_PM_PPB_B2_B3));
    }
}

static void
format_agp_rate(int rate, char *buf, int agp3)
{
  char *c = buf;
  int i;

  for (i=0; i<=2; i++)
    if (rate & (1 << i))
      {
	if (c != buf)
	  *c++ = ',';
	c += sprintf(c, "x%d", 1 << (i + 2*agp3));
      }
  if (c != buf)
    *c = 0;
  else
    strcpy(buf, "<none>");
}

static void
cap_agp(struct device *d, int where, int cap)
{
  u32 t;
  char rate[16];
  int ver, rev;
  int agp3 = 0;

  ver = (cap >> 4) & 0x0f;
  rev = cap & 0x0f;
  printf("AGP version %x.%x\n", ver, rev);
  if (verbose < 2)
    return;
  if (!config_fetch(d, where + PCI_AGP_STATUS, PCI_AGP_SIZEOF - PCI_AGP_STATUS))
    return;
  t = get_conf_long(d, where + PCI_AGP_STATUS);
  if (ver >= 3 && (t & PCI_AGP_STATUS_AGP3))
    agp3 = 1;
  format_agp_rate(t & 7, rate, agp3);
  printf("\t\tStatus: RQ=%d Iso%c ArqSz=%d Cal=%d SBA%c ITACoh%c GART64%c HTrans%c 64bit%c FW%c AGP3%c Rate=%s\n",
	 ((t & PCI_AGP_STATUS_RQ_MASK) >> 24U) + 1,
	 FLAG(t, PCI_AGP_STATUS_ISOCH),
	 ((t & PCI_AGP_STATUS_ARQSZ_MASK) >> 13),
	 ((t & PCI_AGP_STATUS_CAL_MASK) >> 10),
	 FLAG(t, PCI_AGP_STATUS_SBA),
	 FLAG(t, PCI_AGP_STATUS_ITA_COH),
	 FLAG(t, PCI_AGP_STATUS_GART64),
	 FLAG(t, PCI_AGP_STATUS_HTRANS),
	 FLAG(t, PCI_AGP_STATUS_64BIT),
	 FLAG(t, PCI_AGP_STATUS_FW),
	 FLAG(t, PCI_AGP_STATUS_AGP3),
	 rate);
  t = get_conf_long(d, where + PCI_AGP_COMMAND);
  format_agp_rate(t & 7, rate, agp3);
  printf("\t\tCommand: RQ=%d ArqSz=%d Cal=%d SBA%c AGP%c GART64%c 64bit%c FW%c Rate=%s\n",
	 ((t & PCI_AGP_COMMAND_RQ_MASK) >> 24U) + 1,
	 ((t & PCI_AGP_COMMAND_ARQSZ_MASK) >> 13),
	 ((t & PCI_AGP_COMMAND_CAL_MASK) >> 10),
	 FLAG(t, PCI_AGP_COMMAND_SBA),
	 FLAG(t, PCI_AGP_COMMAND_AGP),
	 FLAG(t, PCI_AGP_COMMAND_GART64),
	 FLAG(t, PCI_AGP_COMMAND_64BIT),
	 FLAG(t, PCI_AGP_COMMAND_FW),
	 rate);
}

static void
cap_pcix_nobridge(struct device *d, int where)
{
  u16 command;
  u32 status;
  static const byte max_outstanding[8] = { 1, 2, 3, 4, 8, 12, 16, 32 };

  printf("PCI-X non-bridge device\n");

  if (verbose < 2)
    return;

  if (!config_fetch(d, where + PCI_PCIX_STATUS, 4))
    return;

  command = get_conf_word(d, where + PCI_PCIX_COMMAND);
  status = get_conf_long(d, where + PCI_PCIX_STATUS);
  printf("\t\tCommand: DPERE%c ERO%c RBC=%d OST=%d\n",
	 FLAG(command, PCI_PCIX_COMMAND_DPERE),
	 FLAG(command, PCI_PCIX_COMMAND_ERO),
	 1 << (9 + ((command & PCI_PCIX_COMMAND_MAX_MEM_READ_BYTE_COUNT) >> 2U)),
	 max_outstanding[(command & PCI_PCIX_COMMAND_MAX_OUTSTANDING_SPLIT_TRANS) >> 4U]);
  printf("\t\tStatus: Dev=%02x:%02x.%d 64bit%c 133MHz%c SCD%c USC%c DC=%s DMMRBC=%u DMOST=%u DMCRS=%u RSCEM%c 266MHz%c 533MHz%c\n",
	 (status & PCI_PCIX_STATUS_BUS) >> 8,
	 (status & PCI_PCIX_STATUS_DEVICE) >> 3,
	 (status & PCI_PCIX_STATUS_FUNCTION),
	 FLAG(status, PCI_PCIX_STATUS_64BIT),
	 FLAG(status, PCI_PCIX_STATUS_133MHZ),
	 FLAG(status, PCI_PCIX_STATUS_SC_DISCARDED),
	 FLAG(status, PCI_PCIX_STATUS_UNEXPECTED_SC),
	 ((status & PCI_PCIX_STATUS_DEVICE_COMPLEXITY) ? "bridge" : "simple"),
	 1 << (9 + ((status & PCI_PCIX_STATUS_DESIGNED_MAX_MEM_READ_BYTE_COUNT) >> 21)),
	 max_outstanding[(status & PCI_PCIX_STATUS_DESIGNED_MAX_OUTSTANDING_SPLIT_TRANS) >> 23],
	 1 << (3 + ((status & PCI_PCIX_STATUS_DESIGNED_MAX_CUMULATIVE_READ_SIZE) >> 26)),
	 FLAG(status, PCI_PCIX_STATUS_RCVD_SC_ERR_MESS),
	 FLAG(status, PCI_PCIX_STATUS_266MHZ),
	 FLAG(status, PCI_PCIX_STATUS_533MHZ));
}

static void
cap_pcix_bridge(struct device *d, int where)
{
  static const char * const sec_clock_freq[8] = { "conv", "66MHz", "100MHz", "133MHz", "?4", "?5", "?6", "?7" };
  u16 secstatus;
  u32 status, upstcr, downstcr;

  printf("PCI-X bridge device\n");

  if (verbose < 2)
    return;

  if (!config_fetch(d, where + PCI_PCIX_BRIDGE_STATUS, 12))
    return;

  secstatus = get_conf_word(d, where + PCI_PCIX_BRIDGE_SEC_STATUS);
  printf("\t\tSecondary Status: 64bit%c 133MHz%c SCD%c USC%c SCO%c SRD%c Freq=%s\n",
	 FLAG(secstatus, PCI_PCIX_BRIDGE_SEC_STATUS_64BIT),
	 FLAG(secstatus, PCI_PCIX_BRIDGE_SEC_STATUS_133MHZ),
	 FLAG(secstatus, PCI_PCIX_BRIDGE_SEC_STATUS_SC_DISCARDED),
	 FLAG(secstatus, PCI_PCIX_BRIDGE_SEC_STATUS_UNEXPECTED_SC),
	 FLAG(secstatus, PCI_PCIX_BRIDGE_SEC_STATUS_SC_OVERRUN),
	 FLAG(secstatus, PCI_PCIX_BRIDGE_SEC_STATUS_SPLIT_REQUEST_DELAYED),
	 sec_clock_freq[(secstatus & PCI_PCIX_BRIDGE_SEC_STATUS_CLOCK_FREQ) >> 6]);
  status = get_conf_long(d, where + PCI_PCIX_BRIDGE_STATUS);
  printf("\t\tStatus: Dev=%02x:%02x.%d 64bit%c 133MHz%c SCD%c USC%c SCO%c SRD%c\n",
	 (status & PCI_PCIX_BRIDGE_STATUS_BUS) >> 8,
	 (status & PCI_PCIX_BRIDGE_STATUS_DEVICE) >> 3,
	 (status & PCI_PCIX_BRIDGE_STATUS_FUNCTION),
	 FLAG(status, PCI_PCIX_BRIDGE_STATUS_64BIT),
	 FLAG(status, PCI_PCIX_BRIDGE_STATUS_133MHZ),
	 FLAG(status, PCI_PCIX_BRIDGE_STATUS_SC_DISCARDED),
	 FLAG(status, PCI_PCIX_BRIDGE_STATUS_UNEXPECTED_SC),
	 FLAG(status, PCI_PCIX_BRIDGE_STATUS_SC_OVERRUN),
	 FLAG(status, PCI_PCIX_BRIDGE_STATUS_SPLIT_REQUEST_DELAYED));
  upstcr = get_conf_long(d, where + PCI_PCIX_BRIDGE_UPSTREAM_SPLIT_TRANS_CTRL);
  printf("\t\tUpstream: Capacity=%u CommitmentLimit=%u\n",
	 (upstcr & PCI_PCIX_BRIDGE_STR_CAPACITY),
	 (upstcr >> 16) & 0xffff);
  downstcr = get_conf_long(d, where + PCI_PCIX_BRIDGE_DOWNSTREAM_SPLIT_TRANS_CTRL);
  printf("\t\tDownstream: Capacity=%u CommitmentLimit=%u\n",
	 (downstcr & PCI_PCIX_BRIDGE_STR_CAPACITY),
	 (downstcr >> 16) & 0xffff);
}

static void
cap_pcix(struct device *d, int where)
{
  switch (get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f)
    {
    case PCI_HEADER_TYPE_NORMAL:
      cap_pcix_nobridge(d, where);
      break;
    case PCI_HEADER_TYPE_BRIDGE:
      cap_pcix_bridge(d, where);
      break;
    }
}

static inline char *
ht_link_width(unsigned width)
{
  static char * const widths[8] = { "8bit", "16bit", "[2]", "32bit", "2bit", "4bit", "[6]", "N/C" };
  return widths[width];
}

static inline char *
ht_link_freq(unsigned freq)
{
  static char * const freqs[16] = { "200MHz", "300MHz", "400MHz", "500MHz", "600MHz", "800MHz", "1.0GHz", "1.2GHz",
				    "1.4GHz", "1.6GHz", "[a]", "[b]", "[c]", "[d]", "[e]", "Vend" };
  return freqs[freq];
}

static void
cap_ht_pri(struct device *d, int where, int cmd)
{
  u16 lctr0, lcnf0, lctr1, lcnf1, eh;
  u8 rid, lfrer0, lfcap0, ftr, lfrer1, lfcap1, mbu, mlu, bn;
  char *fmt;

  printf("HyperTransport: Slave or Primary Interface\n");
  if (verbose < 2)
    return;

  if (!config_fetch(d, where + PCI_HT_PRI_LCTR0, PCI_HT_PRI_SIZEOF - PCI_HT_PRI_LCTR0))
    return;
  rid = get_conf_byte(d, where + PCI_HT_PRI_RID);
  if (rid < 0x22 && rid > 0x11)
    printf("\t\t!!! Possibly incomplete decoding\n");

  if (rid >= 0x22)
    fmt = "\t\tCommand: BaseUnitID=%u UnitCnt=%u MastHost%c DefDir%c DUL%c\n";
  else
    fmt = "\t\tCommand: BaseUnitID=%u UnitCnt=%u MastHost%c DefDir%c\n";
  printf(fmt,
	 (cmd & PCI_HT_PRI_CMD_BUID),
	 (cmd & PCI_HT_PRI_CMD_UC) >> 5,
	 FLAG(cmd, PCI_HT_PRI_CMD_MH),
	 FLAG(cmd, PCI_HT_PRI_CMD_DD),
	 FLAG(cmd, PCI_HT_PRI_CMD_DUL));
  lctr0 = get_conf_word(d, where + PCI_HT_PRI_LCTR0);
  if (rid >= 0x22)
    fmt = "\t\tLink Control 0: CFlE%c CST%c CFE%c <LkFail%c Init%c EOC%c TXO%c <CRCErr=%x IsocEn%c LSEn%c ExtCTL%c 64b%c\n";
  else
    fmt = "\t\tLink Control 0: CFlE%c CST%c CFE%c <LkFail%c Init%c EOC%c TXO%c <CRCErr=%x\n";
  printf(fmt,
	 FLAG(lctr0, PCI_HT_LCTR_CFLE),
	 FLAG(lctr0, PCI_HT_LCTR_CST),
	 FLAG(lctr0, PCI_HT_LCTR_CFE),
	 FLAG(lctr0, PCI_HT_LCTR_LKFAIL),
	 FLAG(lctr0, PCI_HT_LCTR_INIT),
	 FLAG(lctr0, PCI_HT_LCTR_EOC),
	 FLAG(lctr0, PCI_HT_LCTR_TXO),
	 (lctr0 & PCI_HT_LCTR_CRCERR) >> 8,
	 FLAG(lctr0, PCI_HT_LCTR_ISOCEN),
	 FLAG(lctr0, PCI_HT_LCTR_LSEN),
	 FLAG(lctr0, PCI_HT_LCTR_EXTCTL),
	 FLAG(lctr0, PCI_HT_LCTR_64B));
  lcnf0 = get_conf_word(d, where + PCI_HT_PRI_LCNF0);
  if (rid >= 0x22)
    fmt = "\t\tLink Config 0: MLWI=%1$s DwFcIn%5$c MLWO=%2$s DwFcOut%6$c LWI=%3$s DwFcInEn%7$c LWO=%4$s DwFcOutEn%8$c\n";
  else
    fmt = "\t\tLink Config 0: MLWI=%s MLWO=%s LWI=%s LWO=%s\n";
  printf(fmt,
	 ht_link_width(lcnf0 & PCI_HT_LCNF_MLWI),
	 ht_link_width((lcnf0 & PCI_HT_LCNF_MLWO) >> 4),
	 ht_link_width((lcnf0 & PCI_HT_LCNF_LWI) >> 8),
	 ht_link_width((lcnf0 & PCI_HT_LCNF_LWO) >> 12),
	 FLAG(lcnf0, PCI_HT_LCNF_DFI),
	 FLAG(lcnf0, PCI_HT_LCNF_DFO),
	 FLAG(lcnf0, PCI_HT_LCNF_DFIE),
	 FLAG(lcnf0, PCI_HT_LCNF_DFOE));
  lctr1 = get_conf_word(d, where + PCI_HT_PRI_LCTR1);
  if (rid >= 0x22)
    fmt = "\t\tLink Control 1: CFlE%c CST%c CFE%c <LkFail%c Init%c EOC%c TXO%c <CRCErr=%x IsocEn%c LSEn%c ExtCTL%c 64b%c\n";
  else
    fmt = "\t\tLink Control 1: CFlE%c CST%c CFE%c <LkFail%c Init%c EOC%c TXO%c <CRCErr=%x\n";
  printf(fmt,
	 FLAG(lctr1, PCI_HT_LCTR_CFLE),
	 FLAG(lctr1, PCI_HT_LCTR_CST),
	 FLAG(lctr1, PCI_HT_LCTR_CFE),
	 FLAG(lctr1, PCI_HT_LCTR_LKFAIL),
	 FLAG(lctr1, PCI_HT_LCTR_INIT),
	 FLAG(lctr1, PCI_HT_LCTR_EOC),
	 FLAG(lctr1, PCI_HT_LCTR_TXO),
	 (lctr1 & PCI_HT_LCTR_CRCERR) >> 8,
	 FLAG(lctr1, PCI_HT_LCTR_ISOCEN),
	 FLAG(lctr1, PCI_HT_LCTR_LSEN),
	 FLAG(lctr1, PCI_HT_LCTR_EXTCTL),
	 FLAG(lctr1, PCI_HT_LCTR_64B));
  lcnf1 = get_conf_word(d, where + PCI_HT_PRI_LCNF1);
  if (rid >= 0x22)
    fmt = "\t\tLink Config 1: MLWI=%1$s DwFcIn%5$c MLWO=%2$s DwFcOut%6$c LWI=%3$s DwFcInEn%7$c LWO=%4$s DwFcOutEn%8$c\n";
  else
    fmt = "\t\tLink Config 1: MLWI=%s MLWO=%s LWI=%s LWO=%s\n";
  printf(fmt,
	 ht_link_width(lcnf1 & PCI_HT_LCNF_MLWI),
	 ht_link_width((lcnf1 & PCI_HT_LCNF_MLWO) >> 4),
	 ht_link_width((lcnf1 & PCI_HT_LCNF_LWI) >> 8),
	 ht_link_width((lcnf1 & PCI_HT_LCNF_LWO) >> 12),
	 FLAG(lcnf1, PCI_HT_LCNF_DFI),
	 FLAG(lcnf1, PCI_HT_LCNF_DFO),
	 FLAG(lcnf1, PCI_HT_LCNF_DFIE),
	 FLAG(lcnf1, PCI_HT_LCNF_DFOE));
  printf("\t\tRevision ID: %u.%02u\n",
	 (rid & PCI_HT_RID_MAJ) >> 5, (rid & PCI_HT_RID_MIN));
  if (rid < 0x22)
    return;
  lfrer0 = get_conf_byte(d, where + PCI_HT_PRI_LFRER0);
  printf("\t\tLink Frequency 0: %s\n", ht_link_freq(lfrer0 & PCI_HT_LFRER_FREQ));
  printf("\t\tLink Error 0: <Prot%c <Ovfl%c <EOC%c CTLTm%c\n",
	 FLAG(lfrer0, PCI_HT_LFRER_PROT),
	 FLAG(lfrer0, PCI_HT_LFRER_OV),
	 FLAG(lfrer0, PCI_HT_LFRER_EOC),
	 FLAG(lfrer0, PCI_HT_LFRER_CTLT));
  lfcap0 = get_conf_byte(d, where + PCI_HT_PRI_LFCAP0);
  printf("\t\tLink Frequency Capability 0: 200MHz%c 300MHz%c 400MHz%c 500MHz%c 600MHz%c 800MHz%c 1.0GHz%c 1.2GHz%c 1.4GHz%c 1.6GHz%c Vend%c\n",
	 FLAG(lfcap0, PCI_HT_LFCAP_200),
	 FLAG(lfcap0, PCI_HT_LFCAP_300),
	 FLAG(lfcap0, PCI_HT_LFCAP_400),
	 FLAG(lfcap0, PCI_HT_LFCAP_500),
	 FLAG(lfcap0, PCI_HT_LFCAP_600),
	 FLAG(lfcap0, PCI_HT_LFCAP_800),
	 FLAG(lfcap0, PCI_HT_LFCAP_1000),
	 FLAG(lfcap0, PCI_HT_LFCAP_1200),
	 FLAG(lfcap0, PCI_HT_LFCAP_1400),
	 FLAG(lfcap0, PCI_HT_LFCAP_1600),
	 FLAG(lfcap0, PCI_HT_LFCAP_VEND));
  ftr = get_conf_byte(d, where + PCI_HT_PRI_FTR);
  printf("\t\tFeature Capability: IsocFC%c LDTSTOP%c CRCTM%c ECTLT%c 64bA%c UIDRD%c\n",
	 FLAG(ftr, PCI_HT_FTR_ISOCFC),
	 FLAG(ftr, PCI_HT_FTR_LDTSTOP),
	 FLAG(ftr, PCI_HT_FTR_CRCTM),
	 FLAG(ftr, PCI_HT_FTR_ECTLT),
	 FLAG(ftr, PCI_HT_FTR_64BA),
	 FLAG(ftr, PCI_HT_FTR_UIDRD));
  lfrer1 = get_conf_byte(d, where + PCI_HT_PRI_LFRER1);
  printf("\t\tLink Frequency 1: %s\n", ht_link_freq(lfrer1 & PCI_HT_LFRER_FREQ));
  printf("\t\tLink Error 1: <Prot%c <Ovfl%c <EOC%c CTLTm%c\n",
	 FLAG(lfrer1, PCI_HT_LFRER_PROT),
	 FLAG(lfrer1, PCI_HT_LFRER_OV),
	 FLAG(lfrer1, PCI_HT_LFRER_EOC),
	 FLAG(lfrer1, PCI_HT_LFRER_CTLT));
  lfcap1 = get_conf_byte(d, where + PCI_HT_PRI_LFCAP1);
  printf("\t\tLink Frequency Capability 1: 200MHz%c 300MHz%c 400MHz%c 500MHz%c 600MHz%c 800MHz%c 1.0GHz%c 1.2GHz%c 1.4GHz%c 1.6GHz%c Vend%c\n",
	 FLAG(lfcap1, PCI_HT_LFCAP_200),
	 FLAG(lfcap1, PCI_HT_LFCAP_300),
	 FLAG(lfcap1, PCI_HT_LFCAP_400),
	 FLAG(lfcap1, PCI_HT_LFCAP_500),
	 FLAG(lfcap1, PCI_HT_LFCAP_600),
	 FLAG(lfcap1, PCI_HT_LFCAP_800),
	 FLAG(lfcap1, PCI_HT_LFCAP_1000),
	 FLAG(lfcap1, PCI_HT_LFCAP_1200),
	 FLAG(lfcap1, PCI_HT_LFCAP_1400),
	 FLAG(lfcap1, PCI_HT_LFCAP_1600),
	 FLAG(lfcap1, PCI_HT_LFCAP_VEND));
  eh = get_conf_word(d, where + PCI_HT_PRI_EH);
  printf("\t\tError Handling: PFlE%c OFlE%c PFE%c OFE%c EOCFE%c RFE%c CRCFE%c SERRFE%c CF%c RE%c PNFE%c ONFE%c EOCNFE%c RNFE%c CRCNFE%c SERRNFE%c\n",
	 FLAG(eh, PCI_HT_EH_PFLE),
	 FLAG(eh, PCI_HT_EH_OFLE),
	 FLAG(eh, PCI_HT_EH_PFE),
	 FLAG(eh, PCI_HT_EH_OFE),
	 FLAG(eh, PCI_HT_EH_EOCFE),
	 FLAG(eh, PCI_HT_EH_RFE),
	 FLAG(eh, PCI_HT_EH_CRCFE),
	 FLAG(eh, PCI_HT_EH_SERRFE),
	 FLAG(eh, PCI_HT_EH_CF),
	 FLAG(eh, PCI_HT_EH_RE),
	 FLAG(eh, PCI_HT_EH_PNFE),
	 FLAG(eh, PCI_HT_EH_ONFE),
	 FLAG(eh, PCI_HT_EH_EOCNFE),
	 FLAG(eh, PCI_HT_EH_RNFE),
	 FLAG(eh, PCI_HT_EH_CRCNFE),
	 FLAG(eh, PCI_HT_EH_SERRNFE));
  mbu = get_conf_byte(d, where + PCI_HT_PRI_MBU);
  mlu = get_conf_byte(d, where + PCI_HT_PRI_MLU);
  printf("\t\tPrefetchable memory behind bridge Upper: %02x-%02x\n", mbu, mlu);
  bn = get_conf_byte(d, where + PCI_HT_PRI_BN);
  printf("\t\tBus Number: %02x\n", bn);
}

static void
cap_ht_sec(struct device *d, int where, int cmd)
{
  u16 lctr, lcnf, ftr, eh;
  u8 rid, lfrer, lfcap, mbu, mlu;
  char *fmt;

  printf("HyperTransport: Host or Secondary Interface\n");
  if (verbose < 2)
    return;

  if (!config_fetch(d, where + PCI_HT_SEC_LCTR, PCI_HT_SEC_SIZEOF - PCI_HT_SEC_LCTR))
    return;
  rid = get_conf_byte(d, where + PCI_HT_SEC_RID);
  if (rid < 0x22 && rid > 0x11)
    printf("\t\t!!! Possibly incomplete decoding\n");

  if (rid >= 0x22)
    fmt = "\t\tCommand: WarmRst%c DblEnd%c DevNum=%u ChainSide%c HostHide%c Slave%c <EOCErr%c DUL%c\n";
  else
    fmt = "\t\tCommand: WarmRst%c DblEnd%c\n";
  printf(fmt,
	 FLAG(cmd, PCI_HT_SEC_CMD_WR),
	 FLAG(cmd, PCI_HT_SEC_CMD_DE),
	 (cmd & PCI_HT_SEC_CMD_DN) >> 2,
	 FLAG(cmd, PCI_HT_SEC_CMD_CS),
	 FLAG(cmd, PCI_HT_SEC_CMD_HH),
	 FLAG(cmd, PCI_HT_SEC_CMD_AS),
	 FLAG(cmd, PCI_HT_SEC_CMD_HIECE),
	 FLAG(cmd, PCI_HT_SEC_CMD_DUL));
  lctr = get_conf_word(d, where + PCI_HT_SEC_LCTR);
  if (rid >= 0x22)
    fmt = "\t\tLink Control: CFlE%c CST%c CFE%c <LkFail%c Init%c EOC%c TXO%c <CRCErr=%x IsocEn%c LSEn%c ExtCTL%c 64b%c\n";
  else
    fmt = "\t\tLink Control: CFlE%c CST%c CFE%c <LkFail%c Init%c EOC%c TXO%c <CRCErr=%x\n";
  printf(fmt,
	 FLAG(lctr, PCI_HT_LCTR_CFLE),
	 FLAG(lctr, PCI_HT_LCTR_CST),
	 FLAG(lctr, PCI_HT_LCTR_CFE),
	 FLAG(lctr, PCI_HT_LCTR_LKFAIL),
	 FLAG(lctr, PCI_HT_LCTR_INIT),
	 FLAG(lctr, PCI_HT_LCTR_EOC),
	 FLAG(lctr, PCI_HT_LCTR_TXO),
	 (lctr & PCI_HT_LCTR_CRCERR) >> 8,
	 FLAG(lctr, PCI_HT_LCTR_ISOCEN),
	 FLAG(lctr, PCI_HT_LCTR_LSEN),
	 FLAG(lctr, PCI_HT_LCTR_EXTCTL),
	 FLAG(lctr, PCI_HT_LCTR_64B));
  lcnf = get_conf_word(d, where + PCI_HT_SEC_LCNF);
  if (rid >= 0x22)
    fmt = "\t\tLink Config: MLWI=%1$s DwFcIn%5$c MLWO=%2$s DwFcOut%6$c LWI=%3$s DwFcInEn%7$c LWO=%4$s DwFcOutEn%8$c\n";
  else
    fmt = "\t\tLink Config: MLWI=%s MLWO=%s LWI=%s LWO=%s\n";
  printf(fmt,
	 ht_link_width(lcnf & PCI_HT_LCNF_MLWI),
	 ht_link_width((lcnf & PCI_HT_LCNF_MLWO) >> 4),
	 ht_link_width((lcnf & PCI_HT_LCNF_LWI) >> 8),
	 ht_link_width((lcnf & PCI_HT_LCNF_LWO) >> 12),
	 FLAG(lcnf, PCI_HT_LCNF_DFI),
	 FLAG(lcnf, PCI_HT_LCNF_DFO),
	 FLAG(lcnf, PCI_HT_LCNF_DFIE),
	 FLAG(lcnf, PCI_HT_LCNF_DFOE));
  printf("\t\tRevision ID: %u.%02u\n",
	 (rid & PCI_HT_RID_MAJ) >> 5, (rid & PCI_HT_RID_MIN));
  if (rid < 0x22)
    return;
  lfrer = get_conf_byte(d, where + PCI_HT_SEC_LFRER);
  printf("\t\tLink Frequency: %s\n", ht_link_freq(lfrer & PCI_HT_LFRER_FREQ));
  printf("\t\tLink Error: <Prot%c <Ovfl%c <EOC%c CTLTm%c\n",
	 FLAG(lfrer, PCI_HT_LFRER_PROT),
	 FLAG(lfrer, PCI_HT_LFRER_OV),
	 FLAG(lfrer, PCI_HT_LFRER_EOC),
	 FLAG(lfrer, PCI_HT_LFRER_CTLT));
  lfcap = get_conf_byte(d, where + PCI_HT_SEC_LFCAP);
  printf("\t\tLink Frequency Capability: 200MHz%c 300MHz%c 400MHz%c 500MHz%c 600MHz%c 800MHz%c 1.0GHz%c 1.2GHz%c 1.4GHz%c 1.6GHz%c Vend%c\n",
	 FLAG(lfcap, PCI_HT_LFCAP_200),
	 FLAG(lfcap, PCI_HT_LFCAP_300),
	 FLAG(lfcap, PCI_HT_LFCAP_400),
	 FLAG(lfcap, PCI_HT_LFCAP_500),
	 FLAG(lfcap, PCI_HT_LFCAP_600),
	 FLAG(lfcap, PCI_HT_LFCAP_800),
	 FLAG(lfcap, PCI_HT_LFCAP_1000),
	 FLAG(lfcap, PCI_HT_LFCAP_1200),
	 FLAG(lfcap, PCI_HT_LFCAP_1400),
	 FLAG(lfcap, PCI_HT_LFCAP_1600),
	 FLAG(lfcap, PCI_HT_LFCAP_VEND));
  ftr = get_conf_word(d, where + PCI_HT_SEC_FTR);
  printf("\t\tFeature Capability: IsocFC%c LDTSTOP%c CRCTM%c ECTLT%c 64bA%c UIDRD%c ExtRS%c UCnfE%c\n",
	 FLAG(ftr, PCI_HT_FTR_ISOCFC),
	 FLAG(ftr, PCI_HT_FTR_LDTSTOP),
	 FLAG(ftr, PCI_HT_FTR_CRCTM),
	 FLAG(ftr, PCI_HT_FTR_ECTLT),
	 FLAG(ftr, PCI_HT_FTR_64BA),
	 FLAG(ftr, PCI_HT_FTR_UIDRD),
	 FLAG(ftr, PCI_HT_SEC_FTR_EXTRS),
	 FLAG(ftr, PCI_HT_SEC_FTR_UCNFE));
  if (ftr & PCI_HT_SEC_FTR_EXTRS)
    {
      eh = get_conf_word(d, where + PCI_HT_SEC_EH);
      printf("\t\tError Handling: PFlE%c OFlE%c PFE%c OFE%c EOCFE%c RFE%c CRCFE%c SERRFE%c CF%c RE%c PNFE%c ONFE%c EOCNFE%c RNFE%c CRCNFE%c SERRNFE%c\n",
	     FLAG(eh, PCI_HT_EH_PFLE),
	     FLAG(eh, PCI_HT_EH_OFLE),
	     FLAG(eh, PCI_HT_EH_PFE),
	     FLAG(eh, PCI_HT_EH_OFE),
	     FLAG(eh, PCI_HT_EH_EOCFE),
	     FLAG(eh, PCI_HT_EH_RFE),
	     FLAG(eh, PCI_HT_EH_CRCFE),
	     FLAG(eh, PCI_HT_EH_SERRFE),
	     FLAG(eh, PCI_HT_EH_CF),
	     FLAG(eh, PCI_HT_EH_RE),
	     FLAG(eh, PCI_HT_EH_PNFE),
	     FLAG(eh, PCI_HT_EH_ONFE),
	     FLAG(eh, PCI_HT_EH_EOCNFE),
	     FLAG(eh, PCI_HT_EH_RNFE),
	     FLAG(eh, PCI_HT_EH_CRCNFE),
	     FLAG(eh, PCI_HT_EH_SERRNFE));
      mbu = get_conf_byte(d, where + PCI_HT_SEC_MBU);
      mlu = get_conf_byte(d, where + PCI_HT_SEC_MLU);
      printf("\t\tPrefetchable memory behind bridge Upper: %02x-%02x\n", mbu, mlu);
    }
}

static void
cap_ht(struct device *d, int where, int cmd)
{
  int type;

  switch (cmd & PCI_HT_CMD_TYP_HI)
    {
    case PCI_HT_CMD_TYP_HI_PRI:
      cap_ht_pri(d, where, cmd);
      return;
    case PCI_HT_CMD_TYP_HI_SEC:
      cap_ht_sec(d, where, cmd);
      return;
    }

  type = cmd & PCI_HT_CMD_TYP;
  switch (type)
    {
    case PCI_HT_CMD_TYP_SW:
      printf("HyperTransport: Switch\n");
      break;
    case PCI_HT_CMD_TYP_IDC:
      printf("HyperTransport: Interrupt Discovery and Configuration\n");
      break;
    case PCI_HT_CMD_TYP_RID:
      printf("HyperTransport: Revision ID: %u.%02u\n",
	     (cmd & PCI_HT_RID_MAJ) >> 5, (cmd & PCI_HT_RID_MIN));
      break;
    case PCI_HT_CMD_TYP_UIDC:
      printf("HyperTransport: UnitID Clumping\n");
      break;
    case PCI_HT_CMD_TYP_ECSA:
      printf("HyperTransport: Extended Configuration Space Access\n");
      break;
    case PCI_HT_CMD_TYP_AM:
      printf("HyperTransport: Address Mapping\n");
      break;
    case PCI_HT_CMD_TYP_MSIM:
      printf("HyperTransport: MSI Mapping Enable%c Fixed%c\n",
	     FLAG(cmd, PCI_HT_MSIM_CMD_EN),
	     FLAG(cmd, PCI_HT_MSIM_CMD_FIXD));
      if (verbose >= 2 && !(cmd & PCI_HT_MSIM_CMD_FIXD))
	{
	  u32 offl, offh;
	  if (!config_fetch(d, where + PCI_HT_MSIM_ADDR_LO, 8))
	    break;
	  offl = get_conf_long(d, where + PCI_HT_MSIM_ADDR_LO);
	  offh = get_conf_long(d, where + PCI_HT_MSIM_ADDR_HI);
	  printf("\t\tMapping Address Base: %016llx\n", ((unsigned long long)offh << 32) | (offl & ~0xfffff));
	}
      break;
    case PCI_HT_CMD_TYP_DR:
      printf("HyperTransport: DirectRoute\n");
      break;
    case PCI_HT_CMD_TYP_VCS:
      printf("HyperTransport: VCSet\n");
      break;
    case PCI_HT_CMD_TYP_RM:
      printf("HyperTransport: Retry Mode\n");
      break;
    case PCI_HT_CMD_TYP_X86:
      printf("HyperTransport: X86 (reserved)\n");
      break;
    default:
      printf("HyperTransport: #%02x\n", type >> 11);
    }
}

static void
cap_msi(struct device *d, int where, int cap)
{
  int is64;
  u32 t;
  u16 w;

  printf("MSI: Enable%c Count=%d/%d Maskable%c 64bit%c\n",
	 FLAG(cap, PCI_MSI_FLAGS_ENABLE),
	 1 << ((cap & PCI_MSI_FLAGS_QSIZE) >> 4),
	 1 << ((cap & PCI_MSI_FLAGS_QMASK) >> 1),
	 FLAG(cap, PCI_MSI_FLAGS_MASK_BIT),
	 FLAG(cap, PCI_MSI_FLAGS_64BIT));
  if (verbose < 2)
    return;
  is64 = cap & PCI_MSI_FLAGS_64BIT;
  if (!config_fetch(d, where + PCI_MSI_ADDRESS_LO, (is64 ? PCI_MSI_DATA_64 : PCI_MSI_DATA_32) + 2 - PCI_MSI_ADDRESS_LO))
    return;
  printf("\t\tAddress: ");
  if (is64)
    {
      t = get_conf_long(d, where + PCI_MSI_ADDRESS_HI);
      w = get_conf_word(d, where + PCI_MSI_DATA_64);
      printf("%08x", t);
    }
  else
    w = get_conf_word(d, where + PCI_MSI_DATA_32);
  t = get_conf_long(d, where + PCI_MSI_ADDRESS_LO);
  printf("%08x  Data: %04x\n", t, w);
  if (cap & PCI_MSI_FLAGS_MASK_BIT)
    {
      u32 mask, pending;

      if (is64)
	{
	  if (!config_fetch(d, where + PCI_MSI_MASK_BIT_64, 8))
	    return;
	  mask = get_conf_long(d, where + PCI_MSI_MASK_BIT_64);
	  pending = get_conf_long(d, where + PCI_MSI_PENDING_64);
	}
      else
        {
	  if (!config_fetch(d, where + PCI_MSI_MASK_BIT_32, 8))
	    return;
	  mask = get_conf_long(d, where + PCI_MSI_MASK_BIT_32);
	  pending = get_conf_long(d, where + PCI_MSI_PENDING_32);
	}
      printf("\t\tMasking: %08x  Pending: %08x\n", mask, pending);
    }
}

static void
fill_info_cap_msi(struct info_obj *caps_obj, struct device *d, int where, int cap)
{
  int is64;
  u16 w;
  char buf[64];
  struct info_obj *msi_obj = info_obj_create_in_obj(caps_obj, "MSI");

  info_obj_add_flag(msi_obj, "Enable", FLAG(cap, PCI_MSI_FLAGS_ENABLE));
  info_obj_add_fmt_buf_str(msi_obj, "Count", buf, sizeof(buf), "%d/%d",
		  1 << ((cap & PCI_MSI_FLAGS_QSIZE) >> 4), 1 << ((cap & PCI_MSI_FLAGS_QMASK) >> 1));
  info_obj_add_flag(msi_obj, "Maskable", FLAG(cap, PCI_MSI_FLAGS_MASK_BIT));
  info_obj_add_flag(msi_obj, "64bit", FLAG(cap, PCI_MSI_FLAGS_64BIT));
  if (verbose < 2)
    return;
  is64 = cap & PCI_MSI_FLAGS_64BIT;
  if (!config_fetch(d, where + PCI_MSI_ADDRESS_LO, (is64 ? PCI_MSI_DATA_64 : PCI_MSI_DATA_32) + 2 - PCI_MSI_ADDRESS_LO))
    return;
  if (is64)
    {
      u32 thigh = get_conf_long(d, where + PCI_MSI_ADDRESS_HI);
      u32 tlow = get_conf_long(d, where + PCI_MSI_ADDRESS_LO);

      info_obj_add_fmt_buf_str(msi_obj, "Address", buf, sizeof(buf), "%08x%08x", thigh, tlow);
      w = get_conf_word(d, where + PCI_MSI_DATA_64);
    }
  else
    {
      u32 t = get_conf_long(d, where + PCI_MSI_ADDRESS_LO);

      info_obj_add_fmt_buf_str(msi_obj, "Address", buf, sizeof(buf), "%08x", t);
      w = get_conf_word(d, where + PCI_MSI_DATA_32);
    }
  info_obj_add_fmt_buf_str(msi_obj, "Data", buf, sizeof(buf), "%04x", w);
  if (cap & PCI_MSI_FLAGS_MASK_BIT)
    {
      u32 mask, pending;

      if (is64)
	{
	  if (!config_fetch(d, where + PCI_MSI_MASK_BIT_64, 8))
	    return;
	  mask = get_conf_long(d, where + PCI_MSI_MASK_BIT_64);
	  pending = get_conf_long(d, where + PCI_MSI_PENDING_64);
	}
      else
        {
	  if (!config_fetch(d, where + PCI_MSI_MASK_BIT_32, 8))
	    return;
	  mask = get_conf_long(d, where + PCI_MSI_MASK_BIT_32);
	  pending = get_conf_long(d, where + PCI_MSI_PENDING_32);
	}
      info_obj_add_fmt_buf_str(msi_obj, "Masking", buf, sizeof(buf), "%08x", mask);
      info_obj_add_fmt_buf_str(msi_obj, "Pending", buf, sizeof(buf), "%08x", pending);
    }
}

static float power_limit(int value, int scale)
{
  static const float scales[4] = { 1.0, 0.1, 0.01, 0.001 };
  return value * scales[scale];
}

static const char *latency_l0s(int value)
{
  static const char *latencies[] = { "<64ns", "<128ns", "<256ns", "<512ns", "<1us", "<2us", "<4us", "unlimited" };
  return latencies[value];
}

static const char *latency_l1(int value)
{
  static const char *latencies[] = { "<1us", "<2us", "<4us", "<8us", "<16us", "<32us", "<64us", "unlimited" };
  return latencies[value];
}

static void cap_express_dev(struct device *d, int where, int type)
{
  u32 t;
  u16 w;

  t = get_conf_long(d, where + PCI_EXP_DEVCAP);
  printf("\t\tDevCap:\tMaxPayload %d bytes, PhantFunc %d",
	128 << (t & PCI_EXP_DEVCAP_PAYLOAD),
	(1 << ((t & PCI_EXP_DEVCAP_PHANTOM) >> 3)) - 1);
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END))
    printf(", Latency L0s %s, L1 %s",
	latency_l0s((t & PCI_EXP_DEVCAP_L0S) >> 6),
	latency_l1((t & PCI_EXP_DEVCAP_L1) >> 9));
  printf("\n");
  printf("\t\t\tExtTag%c", FLAG(t, PCI_EXP_DEVCAP_EXT_TAG));
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END) ||
      (type == PCI_EXP_TYPE_UPSTREAM) || (type == PCI_EXP_TYPE_PCI_BRIDGE))
    printf(" AttnBtn%c AttnInd%c PwrInd%c",
	FLAG(t, PCI_EXP_DEVCAP_ATN_BUT),
	FLAG(t, PCI_EXP_DEVCAP_ATN_IND), FLAG(t, PCI_EXP_DEVCAP_PWR_IND));
  printf(" RBE%c",
	FLAG(t, PCI_EXP_DEVCAP_RBE));
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END))
    printf(" FLReset%c",
	FLAG(t, PCI_EXP_DEVCAP_FLRESET));
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_UPSTREAM) ||
      (type == PCI_EXP_TYPE_PCI_BRIDGE))
    printf(" SlotPowerLimit %.3fW",
	power_limit((t & PCI_EXP_DEVCAP_PWR_VAL) >> 18,
		    (t & PCI_EXP_DEVCAP_PWR_SCL) >> 26));
  printf("\n");

  w = get_conf_word(d, where + PCI_EXP_DEVCTL);
  printf("\t\tDevCtl:\tCorrErr%c NonFatalErr%c FatalErr%c UnsupReq%c\n",
	FLAG(w, PCI_EXP_DEVCTL_CERE),
	FLAG(w, PCI_EXP_DEVCTL_NFERE),
	FLAG(w, PCI_EXP_DEVCTL_FERE),
	FLAG(w, PCI_EXP_DEVCTL_URRE));
  printf("\t\t\tRlxdOrd%c ExtTag%c PhantFunc%c AuxPwr%c NoSnoop%c",
	FLAG(w, PCI_EXP_DEVCTL_RELAXED),
	FLAG(w, PCI_EXP_DEVCTL_EXT_TAG),
	FLAG(w, PCI_EXP_DEVCTL_PHANTOM),
	FLAG(w, PCI_EXP_DEVCTL_AUX_PME),
	FLAG(w, PCI_EXP_DEVCTL_NOSNOOP));
  if (type == PCI_EXP_TYPE_PCI_BRIDGE)
    printf(" BrConfRtry%c", FLAG(w, PCI_EXP_DEVCTL_BCRE));
  if (((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END)) &&
      (t & PCI_EXP_DEVCAP_FLRESET))
    printf(" FLReset%c", FLAG(w, PCI_EXP_DEVCTL_FLRESET));
  printf("\n\t\t\tMaxPayload %d bytes, MaxReadReq %d bytes\n",
	128 << ((w & PCI_EXP_DEVCTL_PAYLOAD) >> 5),
	128 << ((w & PCI_EXP_DEVCTL_READRQ) >> 12));

  w = get_conf_word(d, where + PCI_EXP_DEVSTA);
  printf("\t\tDevSta:\tCorrErr%c NonFatalErr%c FatalErr%c UnsupReq%c AuxPwr%c TransPend%c\n",
	FLAG(w, PCI_EXP_DEVSTA_CED),
	FLAG(w, PCI_EXP_DEVSTA_NFED),
	FLAG(w, PCI_EXP_DEVSTA_FED),
	FLAG(w, PCI_EXP_DEVSTA_URD),
	FLAG(w, PCI_EXP_DEVSTA_AUXPD),
	FLAG(w, PCI_EXP_DEVSTA_TRPND));
}

static void fill_info_express_dev(struct info_obj *exp_obj, struct device *d, int where, int type)
{
  u32 t;
  u16 w;
  struct info_obj *dev_cap_obj, *dev_ctl_obj, *dev_sta_obj, *dev_ctl_re_obj;
  char buf[64];

  t = get_conf_long(d, where + PCI_EXP_DEVCAP);
  dev_cap_obj = info_obj_create_in_obj(exp_obj, "DevCap");
  info_obj_add_fmt_buf_str(dev_cap_obj, "MaxPayload", buf, sizeof(buf), "%d",
	128 << (t & PCI_EXP_DEVCAP_PAYLOAD));
  info_obj_add_fmt_buf_str(dev_cap_obj, "PhantFunc", buf, sizeof(buf), "%d",
	(1 << ((t & PCI_EXP_DEVCAP_PHANTOM) >> 3)) - 1);
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END))
    {
      info_obj_add_str(dev_cap_obj, "L0s", latency_l0s((t & PCI_EXP_DEVCAP_L0S) >> 6));
      info_obj_add_str(dev_cap_obj, "L1", latency_l1((t & PCI_EXP_DEVCAP_L1) >> 9));
    }
  info_obj_add_flag(dev_cap_obj, "ExtTag", FLAG(t, PCI_EXP_DEVCAP_EXT_TAG));
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END) ||
      (type == PCI_EXP_TYPE_UPSTREAM) || (type == PCI_EXP_TYPE_PCI_BRIDGE))
    {
      info_obj_add_flag(dev_cap_obj, "AttnBtn", FLAG(t, PCI_EXP_DEVCAP_ATN_BUT));
      info_obj_add_flag(dev_cap_obj, "AttnInd", FLAG(t, PCI_EXP_DEVCAP_ATN_IND));
      info_obj_add_flag(dev_cap_obj, "PwrInd", FLAG(t, PCI_EXP_DEVCAP_PWR_IND));
    }
  info_obj_add_flag(dev_cap_obj, "RBE", FLAG(t, PCI_EXP_DEVCAP_RBE));
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END))
    info_obj_add_flag(dev_cap_obj, "FLReset", FLAG(t, PCI_EXP_DEVCAP_FLRESET));
  if ((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_UPSTREAM) ||
      (type == PCI_EXP_TYPE_PCI_BRIDGE))
    info_obj_add_fmt_buf_str(dev_cap_obj, "SlotPowerLimit", buf, sizeof(buf), "%.3f",
	power_limit((t & PCI_EXP_DEVCAP_PWR_VAL) >> 18,
		    (t & PCI_EXP_DEVCAP_PWR_SCL) >> 26));

  w = get_conf_word(d, where + PCI_EXP_DEVCTL);
  dev_ctl_obj = info_obj_create_in_obj(exp_obj, "DevCtl");
  dev_ctl_re_obj = info_obj_create_in_obj(dev_ctl_obj, "Report-errors");
  info_obj_add_flag(dev_ctl_re_obj, "Correctable", FLAG(w, PCI_EXP_DEVCTL_CERE));
  info_obj_add_flag(dev_ctl_re_obj, "Non-Fatal", FLAG(w, PCI_EXP_DEVCTL_NFERE));
  info_obj_add_flag(dev_ctl_re_obj, "Fatal", FLAG(w, PCI_EXP_DEVCTL_FERE));
  info_obj_add_flag(dev_ctl_re_obj, "Unsupported", FLAG(w, PCI_EXP_DEVCTL_URRE));
  info_obj_add_flag(dev_ctl_obj, "RlxdOrd", FLAG(w, PCI_EXP_DEVCTL_RELAXED));
  info_obj_add_flag(dev_ctl_obj, "ExtTag", FLAG(w, PCI_EXP_DEVCTL_EXT_TAG));
  info_obj_add_flag(dev_ctl_obj, "PhantFunc", FLAG(w, PCI_EXP_DEVCTL_PHANTOM));
  info_obj_add_flag(dev_ctl_obj, "AuxPwr", FLAG(w, PCI_EXP_DEVCTL_AUX_PME));
  info_obj_add_flag(dev_ctl_obj, "NoSnoop", FLAG(w, PCI_EXP_DEVCTL_NOSNOOP));
  if (type == PCI_EXP_TYPE_PCI_BRIDGE)
    info_obj_add_flag(dev_ctl_obj, "BrConfRtry", FLAG(w, PCI_EXP_DEVCTL_BCRE));
  if (((type == PCI_EXP_TYPE_ENDPOINT) || (type == PCI_EXP_TYPE_LEG_END)) &&
      (t & PCI_EXP_DEVCAP_FLRESET))
    info_obj_add_flag(dev_ctl_obj, "FLReset", FLAG(w, PCI_EXP_DEVCTL_FLRESET));
  info_obj_add_fmt_buf_str(dev_ctl_obj, "MaxPayload", buf, sizeof(buf), "%d",
	128 << ((w & PCI_EXP_DEVCTL_PAYLOAD) >> 5));
  info_obj_add_fmt_buf_str(dev_ctl_obj, "MaxReadReq", buf, sizeof(buf), "%d",
	128 << ((w & PCI_EXP_DEVCTL_READRQ) >> 12));

  w = get_conf_word(d, where + PCI_EXP_DEVSTA);
  dev_sta_obj = info_obj_create_in_obj(exp_obj, "DevSta");
  info_obj_add_flag(dev_sta_obj, "CorrErr", FLAG(w, PCI_EXP_DEVSTA_CED));
  info_obj_add_flag(dev_sta_obj, "UncorrErr", FLAG(w, PCI_EXP_DEVSTA_NFED));
  info_obj_add_flag(dev_sta_obj, "FatalErr", FLAG(w, PCI_EXP_DEVSTA_FED));
  info_obj_add_flag(dev_sta_obj, "UnsuppReq", FLAG(w, PCI_EXP_DEVSTA_URD));
  info_obj_add_flag(dev_sta_obj, "AuxPwr", FLAG(w, PCI_EXP_DEVSTA_AUXPD));
  info_obj_add_flag(dev_sta_obj, "TransPend", FLAG(w, PCI_EXP_DEVSTA_TRPND));
}

static char *link_speed(int speed)
{
  switch (speed)
    {
      case 1:
	return "2.5GT/s";
      case 2:
	return "5GT/s";
      case 3:
	return "8GT/s";
      case 4:
        return "16GT/s";
      default:
	return "unknown";
    }
}

static char *link_compare(int sta, int cap)
{
  if (sta < cap)
    return "downgraded";
  if (sta > cap)
    return "strange";
  return "ok";
}

static char *aspm_support(int code)
{
  switch (code)
    {
      case 0:
        return "not supported";
      case 1:
	return "L0s";
      case 2:
	return "L1";
      case 3:
	return "L0s L1";
      default:
	return "unknown";
    }
}

static const char *aspm_enabled(int code)
{
  static const char *desc[] = { "Disabled", "L0s Enabled", "L1 Enabled", "L0s L1 Enabled" };
  return desc[code];
}

static void cap_express_link(struct device *d, int where, int type)
{
  u32 t, aspm, cap_speed, cap_width, sta_speed, sta_width;
  u16 w;

  t = get_conf_long(d, where + PCI_EXP_LNKCAP);
  aspm = (t & PCI_EXP_LNKCAP_ASPM) >> 10;
  cap_speed = t & PCI_EXP_LNKCAP_SPEED;
  cap_width = (t & PCI_EXP_LNKCAP_WIDTH) >> 4;
  printf("\t\tLnkCap:\tPort #%d, Speed %s, Width x%d, ASPM %s",
	t >> 24,
	link_speed(cap_speed), cap_width,
	aspm_support(aspm));
  if (aspm)
    {
      printf(", Exit Latency ");
      if (aspm & 1)
	printf("L0s %s", latency_l0s((t & PCI_EXP_LNKCAP_L0S) >> 12));
      if (aspm & 2)
	printf("%sL1 %s", (aspm & 1) ? ", " : "",
	    latency_l1((t & PCI_EXP_LNKCAP_L1) >> 15));
    }
  printf("\n");
  printf("\t\t\tClockPM%c Surprise%c LLActRep%c BwNot%c ASPMOptComp%c\n",
	FLAG(t, PCI_EXP_LNKCAP_CLOCKPM),
	FLAG(t, PCI_EXP_LNKCAP_SURPRISE),
	FLAG(t, PCI_EXP_LNKCAP_DLLA),
	FLAG(t, PCI_EXP_LNKCAP_LBNC),
	FLAG(t, PCI_EXP_LNKCAP_AOC));

  w = get_conf_word(d, where + PCI_EXP_LNKCTL);
  printf("\t\tLnkCtl:\tASPM %s;", aspm_enabled(w & PCI_EXP_LNKCTL_ASPM));
  if ((type == PCI_EXP_TYPE_ROOT_PORT) || (type == PCI_EXP_TYPE_ENDPOINT) ||
      (type == PCI_EXP_TYPE_LEG_END) || (type == PCI_EXP_TYPE_PCI_BRIDGE))
    printf(" RCB %d bytes", w & PCI_EXP_LNKCTL_RCB ? 128 : 64);
  printf(" Disabled%c CommClk%c\n\t\t\tExtSynch%c ClockPM%c AutWidDis%c BWInt%c AutBWInt%c\n",
	FLAG(w, PCI_EXP_LNKCTL_DISABLE),
	FLAG(w, PCI_EXP_LNKCTL_CLOCK),
	FLAG(w, PCI_EXP_LNKCTL_XSYNCH),
	FLAG(w, PCI_EXP_LNKCTL_CLOCKPM),
	FLAG(w, PCI_EXP_LNKCTL_HWAUTWD),
	FLAG(w, PCI_EXP_LNKCTL_BWMIE),
	FLAG(w, PCI_EXP_LNKCTL_AUTBWIE));

  w = get_conf_word(d, where + PCI_EXP_LNKSTA);
  sta_speed = w & PCI_EXP_LNKSTA_SPEED;
  sta_width = (w & PCI_EXP_LNKSTA_WIDTH) >> 4;
  printf("\t\tLnkSta:\tSpeed %s (%s), Width x%d (%s)\n",
	link_speed(sta_speed),
	link_compare(sta_speed, cap_speed),
	sta_width,
	link_compare(sta_width, cap_width));
  printf("\t\t\tTrErr%c Train%c SlotClk%c DLActive%c BWMgmt%c ABWMgmt%c\n",
	FLAG(w, PCI_EXP_LNKSTA_TR_ERR),
	FLAG(w, PCI_EXP_LNKSTA_TRAIN),
	FLAG(w, PCI_EXP_LNKSTA_SL_CLK),
	FLAG(w, PCI_EXP_LNKSTA_DL_ACT),
	FLAG(w, PCI_EXP_LNKSTA_BWMGMT),
	FLAG(w, PCI_EXP_LNKSTA_AUTBW));
}

static void fill_info_express_link(struct info_obj *exp_obj, struct device *d, int where, int type)
{
  u32 t, aspm;
  u16 w;
  struct info_obj *lnk_cap_obj, *lnk_ctl_obj, *lnk_sta_obj;
  char buf[64];

  t = get_conf_long(d, where + PCI_EXP_LNKCAP);
  aspm = (t & PCI_EXP_LNKCAP_ASPM) >> 10;
  lnk_cap_obj = info_obj_create_in_obj(exp_obj, "LnkCap");
  info_obj_add_fmt_buf_str(lnk_cap_obj, "Port", buf, sizeof(buf), "%d", t >> 24);
  info_obj_add_str(lnk_cap_obj, "Speed", link_speed(t & PCI_EXP_LNKCAP_SPEED));
  info_obj_add_fmt_buf_str(lnk_cap_obj, "Width", buf, sizeof(buf), "x%d", (t & PCI_EXP_LNKCAP_WIDTH) >> 4);
  info_obj_add_str(lnk_cap_obj, "ASPM", aspm_support(aspm));
  if (aspm)
    {
      if (aspm & 1)
	info_obj_add_str(lnk_cap_obj, "L0s", latency_l0s((t & PCI_EXP_LNKCAP_L0S) >> 12));
      if (aspm & 2)
	info_obj_add_str(lnk_cap_obj, "L1", latency_l1((t & PCI_EXP_LNKCAP_L1) >> 15));
    }
  info_obj_add_flag(lnk_cap_obj, "ClockPM", FLAG(t, PCI_EXP_LNKCAP_CLOCKPM));
  info_obj_add_flag(lnk_cap_obj, "Surprise", FLAG(t, PCI_EXP_LNKCAP_SURPRISE));
  info_obj_add_flag(lnk_cap_obj, "LLActRep", FLAG(t, PCI_EXP_LNKCAP_DLLA));
  info_obj_add_flag(lnk_cap_obj, "BwNot", FLAG(t, PCI_EXP_LNKCAP_LBNC));
  info_obj_add_flag(lnk_cap_obj, "ASPMOptComp", FLAG(t, PCI_EXP_LNKCAP_AOC));

  w = get_conf_word(d, where + PCI_EXP_LNKCTL);
  lnk_ctl_obj = info_obj_create_in_obj(exp_obj, "LnkCtl");
  info_obj_add_str(lnk_ctl_obj, "ASPM", aspm_enabled(w & PCI_EXP_LNKCTL_ASPM));
  if ((type == PCI_EXP_TYPE_ROOT_PORT) || (type == PCI_EXP_TYPE_ENDPOINT) ||
      (type == PCI_EXP_TYPE_LEG_END) || (type == PCI_EXP_TYPE_PCI_BRIDGE))
    info_obj_add_fmt_buf_str(lnk_ctl_obj, "RCB", buf, sizeof(buf), "%d", w & PCI_EXP_LNKCTL_RCB ? 128 : 64);
  info_obj_add_flag(lnk_ctl_obj, "Disabled", FLAG(w, PCI_EXP_LNKCTL_DISABLE));
  info_obj_add_flag(lnk_ctl_obj, "CommClk", FLAG(w, PCI_EXP_LNKCTL_CLOCK));
  info_obj_add_flag(lnk_ctl_obj, "ExtSynch", FLAG(w, PCI_EXP_LNKCTL_XSYNCH));
  info_obj_add_flag(lnk_ctl_obj, "ClockPM", FLAG(w, PCI_EXP_LNKCTL_CLOCKPM));
  info_obj_add_flag(lnk_ctl_obj, "AutWidDis", FLAG(w, PCI_EXP_LNKCTL_HWAUTWD));
  info_obj_add_flag(lnk_ctl_obj, "BWInt", FLAG(w, PCI_EXP_LNKCTL_BWMIE));
  info_obj_add_flag(lnk_ctl_obj, "AutBWInt", FLAG(w, PCI_EXP_LNKCTL_AUTBWIE));

  w = get_conf_word(d, where + PCI_EXP_LNKSTA);
  lnk_sta_obj = info_obj_create_in_obj(exp_obj, "LnkSta");
  info_obj_add_str(lnk_sta_obj, "Speed", link_speed(w & PCI_EXP_LNKSTA_SPEED));
  info_obj_add_fmt_buf_str(lnk_sta_obj, "Width", buf, sizeof(buf), "x%d", (w & PCI_EXP_LNKSTA_WIDTH) >> 4);
  info_obj_add_flag(lnk_sta_obj, "TrErr", FLAG(w, PCI_EXP_LNKSTA_TR_ERR));
  info_obj_add_flag(lnk_sta_obj, "Train", FLAG(w, PCI_EXP_LNKSTA_TRAIN));
  info_obj_add_flag(lnk_sta_obj, "SlotClk", FLAG(w, PCI_EXP_LNKSTA_SL_CLK));
  info_obj_add_flag(lnk_sta_obj, "DLActive", FLAG(w, PCI_EXP_LNKSTA_DL_ACT));
  info_obj_add_flag(lnk_sta_obj, "BWMgmt", FLAG(w, PCI_EXP_LNKSTA_BWMGMT));
  info_obj_add_flag(lnk_sta_obj, "ABWMgmt", FLAG(w, PCI_EXP_LNKSTA_AUTBW));
}

static const char *indicator(int code)
{
  static const char *names[] = { "Unknown", "On", "Blink", "Off" };
  return names[code];
}

static void cap_express_slot(struct device *d, int where)
{
  u32 t;
  u16 w;

  t = get_conf_long(d, where + PCI_EXP_SLTCAP);
  printf("\t\tSltCap:\tAttnBtn%c PwrCtrl%c MRL%c AttnInd%c PwrInd%c HotPlug%c Surprise%c\n",
	FLAG(t, PCI_EXP_SLTCAP_ATNB),
	FLAG(t, PCI_EXP_SLTCAP_PWRC),
	FLAG(t, PCI_EXP_SLTCAP_MRL),
	FLAG(t, PCI_EXP_SLTCAP_ATNI),
	FLAG(t, PCI_EXP_SLTCAP_PWRI),
	FLAG(t, PCI_EXP_SLTCAP_HPC),
	FLAG(t, PCI_EXP_SLTCAP_HPS));
  printf("\t\t\tSlot #%d, PowerLimit %.3fW; Interlock%c NoCompl%c\n",
	(t & PCI_EXP_SLTCAP_PSN) >> 19,
	power_limit((t & PCI_EXP_SLTCAP_PWR_VAL) >> 7, (t & PCI_EXP_SLTCAP_PWR_SCL) >> 15),
	FLAG(t, PCI_EXP_SLTCAP_INTERLOCK),
	FLAG(t, PCI_EXP_SLTCAP_NOCMDCOMP));

  w = get_conf_word(d, where + PCI_EXP_SLTCTL);
  printf("\t\tSltCtl:\tEnable: AttnBtn%c PwrFlt%c MRL%c PresDet%c CmdCplt%c HPIrq%c LinkChg%c\n",
	FLAG(w, PCI_EXP_SLTCTL_ATNB),
	FLAG(w, PCI_EXP_SLTCTL_PWRF),
	FLAG(w, PCI_EXP_SLTCTL_MRLS),
	FLAG(w, PCI_EXP_SLTCTL_PRSD),
	FLAG(w, PCI_EXP_SLTCTL_CMDC),
	FLAG(w, PCI_EXP_SLTCTL_HPIE),
	FLAG(w, PCI_EXP_SLTCTL_LLCHG));
  printf("\t\t\tControl: AttnInd %s, PwrInd %s, Power%c Interlock%c\n",
	indicator((w & PCI_EXP_SLTCTL_ATNI) >> 6),
	indicator((w & PCI_EXP_SLTCTL_PWRI) >> 8),
	FLAG(w, PCI_EXP_SLTCTL_PWRC),
	FLAG(w, PCI_EXP_SLTCTL_INTERLOCK));

  w = get_conf_word(d, where + PCI_EXP_SLTSTA);
  printf("\t\tSltSta:\tStatus: AttnBtn%c PowerFlt%c MRL%c CmdCplt%c PresDet%c Interlock%c\n",
	FLAG(w, PCI_EXP_SLTSTA_ATNB),
	FLAG(w, PCI_EXP_SLTSTA_PWRF),
	FLAG(w, PCI_EXP_SLTSTA_MRL_ST),
	FLAG(w, PCI_EXP_SLTSTA_CMDC),
	FLAG(w, PCI_EXP_SLTSTA_PRES),
	FLAG(w, PCI_EXP_SLTSTA_INTERLOCK));
  printf("\t\t\tChanged: MRL%c PresDet%c LinkState%c\n",
	FLAG(w, PCI_EXP_SLTSTA_MRLS),
	FLAG(w, PCI_EXP_SLTSTA_PRSD),
	FLAG(w, PCI_EXP_SLTSTA_LLCHG));
}

static void fill_info_express_slot(struct info_obj *exp_obj, struct device *d, int where)
{
  u32 t;
  u16 w;
  struct info_obj *slt_cap_obj, *slt_ctl_obj, *slt_sta_obj;
  struct info_obj *slt_ctl_enable_obj, *slt_ctl_control_obj;
  struct info_obj *slt_sta_status_obj, *slt_sta_changed_obj;
  char buf[128];

  t = get_conf_long(d, where + PCI_EXP_SLTCAP);
  slt_cap_obj = info_obj_create_in_obj(exp_obj, "SltCap");
  info_obj_add_flag(slt_cap_obj, "AttnBtn", FLAG(t, PCI_EXP_SLTCAP_ATNB));
  info_obj_add_flag(slt_cap_obj, "PwrCtrl", FLAG(t, PCI_EXP_SLTCAP_PWRC));
  info_obj_add_flag(slt_cap_obj, "MRL", FLAG(t, PCI_EXP_SLTCAP_MRL));
  info_obj_add_flag(slt_cap_obj, "AttnInd", FLAG(t, PCI_EXP_SLTCAP_ATNI));
  info_obj_add_flag(slt_cap_obj, "PwrInd", FLAG(t, PCI_EXP_SLTCAP_PWRI));
  info_obj_add_flag(slt_cap_obj, "HotPlug", FLAG(t, PCI_EXP_SLTCAP_HPC));
  info_obj_add_flag(slt_cap_obj, "Surprise", FLAG(t, PCI_EXP_SLTCAP_HPS));
  info_obj_add_fmt_buf_str(slt_cap_obj, "Slot", buf, sizeof(buf), "%d", (t & PCI_EXP_SLTCAP_PSN) >> 19);
  info_obj_add_fmt_buf_str(slt_cap_obj, "PowerLimit", buf, sizeof(buf), "%.3f",
		  power_limit((t & PCI_EXP_SLTCAP_PWR_VAL) >> 7, (t & PCI_EXP_SLTCAP_PWR_SCL) >> 15));
  info_obj_add_flag(slt_cap_obj, "Interlock", FLAG(t, PCI_EXP_SLTCAP_INTERLOCK));
  info_obj_add_flag(slt_cap_obj, "NoCompl", FLAG(t, PCI_EXP_SLTCAP_NOCMDCOMP));

  w = get_conf_word(d, where + PCI_EXP_SLTCTL);
  slt_ctl_obj = info_obj_create_in_obj(exp_obj, "SltCtl");
  slt_ctl_enable_obj = info_obj_create_in_obj(slt_ctl_obj, "Enable");
  info_obj_add_flag(slt_ctl_enable_obj, "AttnBtn", FLAG(w, PCI_EXP_SLTCTL_ATNB));
  info_obj_add_flag(slt_ctl_enable_obj, "PwrFlt", FLAG(w, PCI_EXP_SLTCTL_PWRF));
  info_obj_add_flag(slt_ctl_enable_obj, "MRL", FLAG(w, PCI_EXP_SLTCTL_MRLS));
  info_obj_add_flag(slt_ctl_enable_obj, "PresDet", FLAG(w, PCI_EXP_SLTCTL_PRSD));
  info_obj_add_flag(slt_ctl_enable_obj, "CmdCplt", FLAG(w, PCI_EXP_SLTCTL_CMDC));
  info_obj_add_flag(slt_ctl_enable_obj, "HPIrq", FLAG(w, PCI_EXP_SLTCTL_HPIE));
  info_obj_add_flag(slt_ctl_enable_obj, "LinkChg", FLAG(w, PCI_EXP_SLTCTL_LLCHG));
  slt_ctl_control_obj = info_obj_create_in_obj(slt_ctl_obj, "Control");
  info_obj_add_str(slt_ctl_control_obj, "AttnInd", indicator((w & PCI_EXP_SLTCTL_ATNI) >> 6));
  info_obj_add_str(slt_ctl_control_obj, "PwrInd", indicator((w & PCI_EXP_SLTCTL_PWRI) >> 8));
  info_obj_add_flag(slt_ctl_control_obj, "Power", FLAG(w, PCI_EXP_SLTCTL_PWRC));
  info_obj_add_flag(slt_ctl_control_obj, "Inrelock", FLAG(w, PCI_EXP_SLTCTL_INTERLOCK));

  w = get_conf_word(d, where + PCI_EXP_SLTSTA);
  slt_sta_obj = info_obj_create_in_obj(exp_obj, "SltSta");
  slt_sta_status_obj = info_obj_create_in_obj(slt_sta_obj, "Status");
  info_obj_add_flag(slt_sta_status_obj, "AttnBtn", FLAG(w, PCI_EXP_SLTSTA_ATNB));
  info_obj_add_flag(slt_sta_status_obj, "PowerFlt", FLAG(w, PCI_EXP_SLTSTA_PWRF));
  info_obj_add_flag(slt_sta_status_obj, "MRL", FLAG(w, PCI_EXP_SLTSTA_MRL_ST));
  info_obj_add_flag(slt_sta_status_obj, "CmdCplt", FLAG(w, PCI_EXP_SLTSTA_CMDC));
  info_obj_add_flag(slt_sta_status_obj, "PresDet", FLAG(w, PCI_EXP_SLTSTA_PRES));
  info_obj_add_flag(slt_sta_status_obj, "Interlock", FLAG(w, PCI_EXP_SLTSTA_INTERLOCK));
  slt_sta_changed_obj = info_obj_create_in_obj(slt_sta_obj, "Changed");
  info_obj_add_flag(slt_sta_changed_obj, "MRL", FLAG(w, PCI_EXP_SLTSTA_MRLS));
  info_obj_add_flag(slt_sta_changed_obj, "PresDet", FLAG(w, PCI_EXP_SLTSTA_PRSD));
  info_obj_add_flag(slt_sta_changed_obj, "LinkState", FLAG(w, PCI_EXP_SLTSTA_LLCHG));
}

static void cap_express_root(struct device *d, int where)
{
  u32 w = get_conf_word(d, where + PCI_EXP_RTCTL);
  printf("\t\tRootCtl: ErrCorrectable%c ErrNon-Fatal%c ErrFatal%c PMEIntEna%c CRSVisible%c\n",
	FLAG(w, PCI_EXP_RTCTL_SECEE),
	FLAG(w, PCI_EXP_RTCTL_SENFEE),
	FLAG(w, PCI_EXP_RTCTL_SEFEE),
	FLAG(w, PCI_EXP_RTCTL_PMEIE),
	FLAG(w, PCI_EXP_RTCTL_CRSVIS));

  w = get_conf_word(d, where + PCI_EXP_RTCAP);
  printf("\t\tRootCap: CRSVisible%c\n",
	FLAG(w, PCI_EXP_RTCAP_CRSVIS));

  w = get_conf_long(d, where + PCI_EXP_RTSTA);
  printf("\t\tRootSta: PME ReqID %04x, PMEStatus%c PMEPending%c\n",
	w & PCI_EXP_RTSTA_PME_REQID,
	FLAG(w, PCI_EXP_RTSTA_PME_STATUS),
	FLAG(w, PCI_EXP_RTSTA_PME_PENDING));
}

static void fill_info_express_root(struct info_obj *exp_obj, struct device *d, int where)
{
  struct info_obj *root_cap_obj, *root_ctl_obj, *root_sta_obj;

  u32 w = get_conf_word(d, where + PCI_EXP_RTCTL);
  root_ctl_obj = info_obj_create_in_obj(exp_obj, "RootCtl");
  info_obj_add_flag(root_ctl_obj, "ErrCorrectable", FLAG(w, PCI_EXP_RTCTL_SECEE));
  info_obj_add_flag(root_ctl_obj, "ErrNon-Fatal", FLAG(w, PCI_EXP_RTCTL_SENFEE));
  info_obj_add_flag(root_ctl_obj, "ErrFatal", FLAG(w, PCI_EXP_RTCTL_SEFEE));
  info_obj_add_flag(root_ctl_obj, "PMEIntEna", FLAG(w, PCI_EXP_RTCTL_PMEIE));
  info_obj_add_flag(root_ctl_obj, "CRSVisible", FLAG(w, PCI_EXP_RTCTL_CRSVIS));

  w = get_conf_word(d, where + PCI_EXP_RTCAP);
  root_cap_obj = info_obj_create_in_obj(exp_obj, "RootCap");
  info_obj_add_flag(root_cap_obj, "CRSVisible", FLAG(w, PCI_EXP_RTCAP_CRSVIS));

  w = get_conf_long(d, where + PCI_EXP_RTSTA);
  root_sta_obj = info_obj_create_in_obj(exp_obj, "RootSta");
  info_obj_add_fmt_str(root_sta_obj, "PME-ReqID", 5, "%04x", w & PCI_EXP_RTSTA_PME_REQID);
  info_obj_add_flag(root_sta_obj, "PMEStatus", FLAG(w, PCI_EXP_RTSTA_PME_STATUS));
  info_obj_add_flag(root_sta_obj, "PMEPending", FLAG(w, PCI_EXP_RTSTA_PME_PENDING));
}

static const char *cap_express_dev2_timeout_range(int type)
{
  /* Decode Completion Timeout Ranges. */
  switch (type)
    {
      case 0:
	return "Not Supported";
      case 1:
	return "Range A";
      case 2:
	return "Range B";
      case 3:
	return "Range AB";
      case 6:
	return "Range BC";
      case 7:
	return "Range ABC";
      case 14:
	return "Range BCD";
      case 15:
	return "Range ABCD";
      default:
	return "Unknown";
    }
}

static const char *cap_express_dev2_timeout_value(int type)
{
  /* Decode Completion Timeout Value. */
  switch (type)
    {
      case 0:
	return "50us to 50ms";
      case 1:
	return "50us to 100us";
      case 2:
	return "1ms to 10ms";
      case 5:
	return "16ms to 55ms";
      case 6:
	return "65ms to 210ms";
      case 9:
	return "260ms to 900ms";
      case 10:
	return "1s to 3.5s";
      case 13:
	return "4s to 13s";
      case 14:
	return "17s to 64s";
      default:
	return "Unknown";
    }
}

static const char *cap_express_devcap2_obff(int obff)
{
  switch (obff)
    {
      case 1:
        return "Via message";
      case 2:
        return "Via WAKE#";
      case 3:
        return "Via message/WAKE#";
      default:
        return "Not Supported";
    }
}

static const char *cap_express_devctl2_obff(int obff)
{
  switch (obff)
    {
      case 0:
        return "Disabled";
      case 1:
        return "Via message A";
      case 2:
        return "Via message B";
      case 3:
        return "Via WAKE#";
      default:
        return "Unknown";
    }
}

static int
device_has_memory_space_bar(struct device *d)
{
  struct pci_dev *p = d->dev;
  int i, found = 0;

  for (i=0; i<6; i++)
    if (p->base_addr[i] && p->size[i])
      {
        if (!(p->base_addr[i] & PCI_BASE_ADDRESS_SPACE_IO))
          {
            found = 1;
            break;
          }
      }
  return found;
}

static void cap_express_dev2(struct device *d, int where, int type)
{
  u32 l;
  u16 w;
  int has_mem_bar = device_has_memory_space_bar(d);

  l = get_conf_long(d, where + PCI_EXP_DEVCAP2);
  printf("\t\tDevCap2: Completion Timeout: %s, TimeoutDis%c, LTR%c, OBFF %s",
	cap_express_dev2_timeout_range(PCI_EXP_DEV2_TIMEOUT_RANGE(l)),
	FLAG(l, PCI_EXP_DEV2_TIMEOUT_DIS),
	FLAG(l, PCI_EXP_DEVCAP2_LTR),
	cap_express_devcap2_obff(PCI_EXP_DEVCAP2_OBFF(l)));
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_DOWNSTREAM)
    printf(" ARIFwd%c\n", FLAG(l, PCI_EXP_DEV2_ARI));
  else
    printf("\n");
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
      type == PCI_EXP_TYPE_DOWNSTREAM || has_mem_bar)
    {
       printf("\t\t\t AtomicOpsCap:");
       if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
           type == PCI_EXP_TYPE_DOWNSTREAM)
         printf(" Routing%c", FLAG(l, PCI_EXP_DEVCAP2_ATOMICOP_ROUTING));
       if (type == PCI_EXP_TYPE_ROOT_PORT || has_mem_bar)
         printf(" 32bit%c 64bit%c 128bitCAS%c",
		FLAG(l, PCI_EXP_DEVCAP2_32BIT_ATOMICOP_COMP),
		FLAG(l, PCI_EXP_DEVCAP2_64BIT_ATOMICOP_COMP),
		FLAG(l, PCI_EXP_DEVCAP2_128BIT_CAS_COMP));
       printf("\n");
    }

  w = get_conf_word(d, where + PCI_EXP_DEVCTL2);
  printf("\t\tDevCtl2: Completion Timeout: %s, TimeoutDis%c, LTR%c, OBFF %s",
	cap_express_dev2_timeout_value(PCI_EXP_DEV2_TIMEOUT_VALUE(w)),
	FLAG(w, PCI_EXP_DEV2_TIMEOUT_DIS),
	FLAG(w, PCI_EXP_DEV2_LTR),
	cap_express_devctl2_obff(PCI_EXP_DEV2_OBFF(w)));
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_DOWNSTREAM)
    printf(" ARIFwd%c\n", FLAG(w, PCI_EXP_DEV2_ARI));
  else
    printf("\n");
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
      type == PCI_EXP_TYPE_DOWNSTREAM || type == PCI_EXP_TYPE_ENDPOINT ||
      type == PCI_EXP_TYPE_ROOT_INT_EP || type == PCI_EXP_TYPE_LEG_END)
    {
      printf("\t\t\t AtomicOpsCtl:");
      if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_ENDPOINT ||
          type == PCI_EXP_TYPE_ROOT_INT_EP || type == PCI_EXP_TYPE_LEG_END)
        printf(" ReqEn%c", FLAG(w, PCI_EXP_DEV2_ATOMICOP_REQUESTER_EN));
      if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
          type == PCI_EXP_TYPE_DOWNSTREAM)
        printf(" EgressBlck%c", FLAG(w, PCI_EXP_DEV2_ATOMICOP_EGRESS_BLOCK));
      printf("\n");
    }
}

static void fill_info_express_dev2(struct info_obj *exp_obj, struct device *d, int where, int type)
{
  u32 l;
  u16 w;
  int has_mem_bar = device_has_memory_space_bar(d);
  struct info_obj *dev_cap2_obj, *dev_ctl2_obj;

  l = get_conf_long(d, where + PCI_EXP_DEVCAP2);
  dev_cap2_obj = info_obj_create_in_obj(exp_obj, "DevCap2");
  info_obj_add_str(dev_cap2_obj, "Completion-Timeout", cap_express_dev2_timeout_range(PCI_EXP_DEV2_TIMEOUT_RANGE(l)));
  info_obj_add_flag(dev_cap2_obj, "TimeoutDis", FLAG(l, PCI_EXP_DEV2_TIMEOUT_DIS));
  info_obj_add_flag(dev_cap2_obj, "LTR", FLAG(l, PCI_EXP_DEVCAP2_LTR));
  info_obj_add_str(dev_cap2_obj, "OBFF", cap_express_devcap2_obff(PCI_EXP_DEVCAP2_OBFF(l)));
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_DOWNSTREAM)
    info_obj_add_flag(dev_cap2_obj, "ARIFwd", FLAG(l, PCI_EXP_DEV2_ARI));
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
      type == PCI_EXP_TYPE_DOWNSTREAM || has_mem_bar)
    {
      struct info_obj *dev_cap2_aoc_obj = info_obj_create_in_obj(dev_cap2_obj, "AtomicOpsCap");

      if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
          type == PCI_EXP_TYPE_DOWNSTREAM)
	info_obj_add_flag(dev_cap2_aoc_obj, "Routing", FLAG(l, PCI_EXP_DEVCAP2_ATOMICOP_ROUTING));
      if (type == PCI_EXP_TYPE_ROOT_PORT || has_mem_bar)
	{
	  info_obj_add_flag(dev_cap2_aoc_obj, "32bit", FLAG(l, PCI_EXP_DEVCAP2_32BIT_ATOMICOP_COMP));
	  info_obj_add_flag(dev_cap2_aoc_obj, "64bit", FLAG(l, PCI_EXP_DEVCAP2_64BIT_ATOMICOP_COMP));
	  info_obj_add_flag(dev_cap2_aoc_obj, "128bitCAS", FLAG(l, PCI_EXP_DEVCAP2_128BIT_CAS_COMP));
	}
    }

  w = get_conf_word(d, where + PCI_EXP_DEVCTL2);
  dev_ctl2_obj = info_obj_create_in_obj(exp_obj, "DevCtl2");
  info_obj_add_str(dev_ctl2_obj, "Completion-Timeout", cap_express_dev2_timeout_value(PCI_EXP_DEV2_TIMEOUT_VALUE(w)));
  info_obj_add_flag(dev_ctl2_obj, "TimeoutDis", FLAG(w, PCI_EXP_DEV2_TIMEOUT_DIS));
  info_obj_add_flag(dev_ctl2_obj, "LTR", FLAG(w, PCI_EXP_DEV2_LTR));
  info_obj_add_str(dev_ctl2_obj, "OBFF", cap_express_devctl2_obff(PCI_EXP_DEV2_OBFF(w)));
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_DOWNSTREAM)
    info_obj_add_flag(dev_ctl2_obj, "ARIFwd", FLAG(w, PCI_EXP_DEV2_ARI));
  if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
      type == PCI_EXP_TYPE_DOWNSTREAM || type == PCI_EXP_TYPE_ENDPOINT ||
      type == PCI_EXP_TYPE_ROOT_INT_EP || type == PCI_EXP_TYPE_LEG_END)
    {
      struct info_obj *dev_ctl2_aoc_obj = info_obj_create_in_obj(dev_ctl2_obj, "AtomicOpsCtl");

      if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_ENDPOINT ||
          type == PCI_EXP_TYPE_ROOT_INT_EP || type == PCI_EXP_TYPE_LEG_END)
	info_obj_add_flag(dev_ctl2_aoc_obj, "ReqEn", FLAG(w, PCI_EXP_DEV2_ATOMICOP_REQUESTER_EN));
      if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_UPSTREAM ||
          type == PCI_EXP_TYPE_DOWNSTREAM)
	info_obj_add_flag(dev_ctl2_aoc_obj, "EgressBlck", FLAG(w, PCI_EXP_DEV2_ATOMICOP_EGRESS_BLOCK));
    }
}


static const char *cap_express_link2_speed(int type)
{
  switch (type)
    {
      case 0: /* hardwire to 0 means only the 2.5GT/s is supported */
      case 1:
	return "2.5GT/s";
      case 2:
	return "5GT/s";
      case 3:
	return "8GT/s";
      case 4:
        return "16GT/s";
      default:
	return "Unknown";
    }
}

static const char *cap_express_link2_deemphasis(int type)
{
  switch (type)
    {
      case 0:
	return "-6dB";
      case 1:
	return "-3.5dB";
      default:
	return "Unknown";
    }
}

static const char *cap_express_link2_transmargin(int type)
{
  switch (type)
    {
      case 0:
	return "Normal Operating Range";
      case 1:
	return "800-1200mV(full-swing)/400-700mV(half-swing)";
      case 2:
      case 3:
      case 4:
      case 5:
	return "200-400mV(full-swing)/100-200mV(half-swing)";
      default:
	return "Unknown";
    }
}

static void cap_express_link2(struct device *d, int where, int type)
{
  u16 w;

  if (!((type == PCI_EXP_TYPE_ENDPOINT || type == PCI_EXP_TYPE_LEG_END) &&
	(d->dev->dev != 0 || d->dev->func != 0))) {
    w = get_conf_word(d, where + PCI_EXP_LNKCTL2);
    printf("\t\tLnkCtl2: Target Link Speed: %s, EnterCompliance%c SpeedDis%c",
	cap_express_link2_speed(PCI_EXP_LNKCTL2_SPEED(w)),
	FLAG(w, PCI_EXP_LNKCTL2_CMPLNC),
	FLAG(w, PCI_EXP_LNKCTL2_SPEED_DIS));
    if (type == PCI_EXP_TYPE_DOWNSTREAM)
      printf(", Selectable De-emphasis: %s",
	cap_express_link2_deemphasis(PCI_EXP_LNKCTL2_DEEMPHASIS(w)));
    printf("\n"
	"\t\t\t Transmit Margin: %s, EnterModifiedCompliance%c ComplianceSOS%c\n"
	"\t\t\t Compliance De-emphasis: %s\n",
	cap_express_link2_transmargin(PCI_EXP_LNKCTL2_MARGIN(w)),
	FLAG(w, PCI_EXP_LNKCTL2_MOD_CMPLNC),
	FLAG(w, PCI_EXP_LNKCTL2_CMPLNC_SOS),
	cap_express_link2_deemphasis(PCI_EXP_LNKCTL2_COM_DEEMPHASIS(w)));
  }

  w = get_conf_word(d, where + PCI_EXP_LNKSTA2);
  printf("\t\tLnkSta2: Current De-emphasis Level: %s, EqualizationComplete%c, EqualizationPhase1%c\n"
	"\t\t\t EqualizationPhase2%c, EqualizationPhase3%c, LinkEqualizationRequest%c\n",
	cap_express_link2_deemphasis(PCI_EXP_LINKSTA2_DEEMPHASIS(w)),
	FLAG(w, PCI_EXP_LINKSTA2_EQU_COMP),
	FLAG(w, PCI_EXP_LINKSTA2_EQU_PHASE1),
	FLAG(w, PCI_EXP_LINKSTA2_EQU_PHASE2),
	FLAG(w, PCI_EXP_LINKSTA2_EQU_PHASE3),
	FLAG(w, PCI_EXP_LINKSTA2_EQU_REQ));
}

static void fill_info_express_link2(struct info_obj *exp_obj, struct device *d, int where, int type)
{
  u16 w;
  struct info_obj *lnk_sta2_obj;

  if (!((type == PCI_EXP_TYPE_ENDPOINT || type == PCI_EXP_TYPE_LEG_END) &&
	(d->dev->dev != 0 || d->dev->func != 0))) {
    struct info_obj *lnk_ctl2_obj;

    w = get_conf_word(d, where + PCI_EXP_LNKCTL2);
    lnk_ctl2_obj = info_obj_create_in_obj(exp_obj, "LnkCtl2");
    info_obj_add_str(lnk_ctl2_obj, "Target-Link-Speed", cap_express_link2_speed(PCI_EXP_LNKCTL2_SPEED(w)));
    info_obj_add_flag(lnk_ctl2_obj, "EnterCompliance", FLAG(w, PCI_EXP_LNKCTL2_CMPLNC));
    info_obj_add_flag(lnk_ctl2_obj, "SpeedDis", FLAG(w, PCI_EXP_LNKCTL2_SPEED_DIS));
    if (type == PCI_EXP_TYPE_DOWNSTREAM)
      info_obj_add_str(lnk_ctl2_obj, "Selectable-De-emphasis", cap_express_link2_deemphasis(PCI_EXP_LNKCTL2_DEEMPHASIS(w)));
    info_obj_add_str(lnk_ctl2_obj, "Transmit-Margin", cap_express_link2_transmargin(PCI_EXP_LNKCTL2_MARGIN(w)));
    info_obj_add_flag(lnk_ctl2_obj, "EnterModifiedCompliance", FLAG(w, PCI_EXP_LNKCTL2_MOD_CMPLNC));
    info_obj_add_flag(lnk_ctl2_obj, "ComplianceSOS", FLAG(w, PCI_EXP_LNKCTL2_CMPLNC_SOS));
    info_obj_add_str(lnk_ctl2_obj, "Compliance-De-emphasis", cap_express_link2_deemphasis(PCI_EXP_LNKCTL2_COM_DEEMPHASIS(w)));
  }

  w = get_conf_word(d, where + PCI_EXP_LNKSTA2);
  lnk_sta2_obj = info_obj_create_in_obj(exp_obj, "LnkSta2");
  info_obj_add_str(lnk_sta2_obj, "Current-De-emphasis-Level", cap_express_link2_deemphasis(PCI_EXP_LINKSTA2_DEEMPHASIS(w)));
  info_obj_add_flag(lnk_sta2_obj, "EqualizationComplete", FLAG(w, PCI_EXP_LINKSTA2_EQU_COMP));
  info_obj_add_flag(lnk_sta2_obj, "EqualizationPhase1", FLAG(w, PCI_EXP_LINKSTA2_EQU_PHASE1));
  info_obj_add_flag(lnk_sta2_obj, "EqualizationPhase2", FLAG(w, PCI_EXP_LINKSTA2_EQU_PHASE2));
  info_obj_add_flag(lnk_sta2_obj, "EqualizationPhase3", FLAG(w, PCI_EXP_LINKSTA2_EQU_PHASE3));
  info_obj_add_flag(lnk_sta2_obj, "LinkEqualizationRequest", FLAG(w, PCI_EXP_LINKSTA2_EQU_REQ));
}

static void cap_express_slot2(struct device *d UNUSED, int where UNUSED)
{
  /* No capabilities that require this field in PCIe rev2.0 spec. */
}

static int
cap_express(struct device *d, int where, int cap)
{
  int type = (cap & PCI_EXP_FLAGS_TYPE) >> 4;
  int size;
  int slot = 0;
  int link = 1;

  printf("Express ");
  if (verbose >= 2)
    printf("(v%d) ", cap & PCI_EXP_FLAGS_VERS);
  switch (type)
    {
    case PCI_EXP_TYPE_ENDPOINT:
      printf("Endpoint");
      break;
    case PCI_EXP_TYPE_LEG_END:
      printf("Legacy Endpoint");
      break;
    case PCI_EXP_TYPE_ROOT_PORT:
      slot = cap & PCI_EXP_FLAGS_SLOT;
      printf("Root Port (Slot%c)", FLAG(cap, PCI_EXP_FLAGS_SLOT));
      break;
    case PCI_EXP_TYPE_UPSTREAM:
      printf("Upstream Port");
      break;
    case PCI_EXP_TYPE_DOWNSTREAM:
      slot = cap & PCI_EXP_FLAGS_SLOT;
      printf("Downstream Port (Slot%c)", FLAG(cap, PCI_EXP_FLAGS_SLOT));
      break;
    case PCI_EXP_TYPE_PCI_BRIDGE:
      printf("PCI-Express to PCI/PCI-X Bridge");
      break;
    case PCI_EXP_TYPE_PCIE_BRIDGE:
      slot = cap & PCI_EXP_FLAGS_SLOT;
      printf("PCI/PCI-X to PCI-Express Bridge (Slot%c)",
	     FLAG(cap, PCI_EXP_FLAGS_SLOT));
      break;
    case PCI_EXP_TYPE_ROOT_INT_EP:
      link = 0;
      printf("Root Complex Integrated Endpoint");
      break;
    case PCI_EXP_TYPE_ROOT_EC:
      link = 0;
      printf("Root Complex Event Collector");
      break;
    default:
      printf("Unknown type %d", type);
  }
  printf(", MSI %02x\n", (cap & PCI_EXP_FLAGS_IRQ) >> 9);
  if (verbose < 2)
    return type;

  size = 16;
  if (slot)
    size = 24;
  if (type == PCI_EXP_TYPE_ROOT_PORT)
    size = 32;
  if (!config_fetch(d, where + PCI_EXP_DEVCAP, size))
    return type;

  cap_express_dev(d, where, type);
  if (link)
    cap_express_link(d, where, type);
  if (slot)
    cap_express_slot(d, where);
  if (type == PCI_EXP_TYPE_ROOT_PORT)
    cap_express_root(d, where);

  if ((cap & PCI_EXP_FLAGS_VERS) < 2)
    return type;

  size = 16;
  if (slot)
    size = 24;
  if (!config_fetch(d, where + PCI_EXP_DEVCAP2, size))
    return type;

  cap_express_dev2(d, where, type);
  if (link)
    cap_express_link2(d, where, type);
  if (slot)
    cap_express_slot2(d, where);
  return type;
}

static int
fill_info_cap_express(struct info_obj *caps_obj, struct device *d, int where, int cap)
{
  int type = (cap & PCI_EXP_FLAGS_TYPE) >> 4;
  int size;
  int slot = 0;
  int link = 1;
  struct info_obj *express_obj = info_obj_create_in_obj(caps_obj, "express");
  char buf[128];

  if (verbose >= 2)
    info_obj_add_fmt_buf_str(express_obj, "ver", buf, sizeof(buf), "%d", cap & PCI_EXP_FLAGS_VERS);
  switch (type)
    {
    case PCI_EXP_TYPE_ENDPOINT:
      snprintf(buf, sizeof(buf), "Endpoint");
      break;
    case PCI_EXP_TYPE_LEG_END:
      snprintf(buf, sizeof(buf), "Legacy Endpoint");
      break;
    case PCI_EXP_TYPE_ROOT_PORT:
      slot = cap & PCI_EXP_FLAGS_SLOT;
      snprintf(buf, sizeof(buf), "Root Port (Slot%c)", FLAG(cap, PCI_EXP_FLAGS_SLOT));
      break;
    case PCI_EXP_TYPE_UPSTREAM:
      snprintf(buf, sizeof(buf), "Upstream Port");
      break;
    case PCI_EXP_TYPE_DOWNSTREAM:
      slot = cap & PCI_EXP_FLAGS_SLOT;
      snprintf(buf, sizeof(buf), "Downstream Port (Slot%c)", FLAG(cap, PCI_EXP_FLAGS_SLOT));
      break;
    case PCI_EXP_TYPE_PCI_BRIDGE:
      snprintf(buf, sizeof(buf), "PCI-Express to PCI/PCI-X Bridge");
      break;
    case PCI_EXP_TYPE_PCIE_BRIDGE:
      slot = cap & PCI_EXP_FLAGS_SLOT;
      snprintf(buf, sizeof(buf), "PCI/PCI-X to PCI-Express Bridge (Slot%c)",
	     FLAG(cap, PCI_EXP_FLAGS_SLOT));
      break;
    case PCI_EXP_TYPE_ROOT_INT_EP:
      link = 0;
      snprintf(buf, sizeof(buf), "Root Complex Integrated Endpoint");
      break;
    case PCI_EXP_TYPE_ROOT_EC:
      link = 0;
      snprintf(buf, sizeof(buf), "Root Complex Event Collector");
      break;
    default:
      snprintf(buf, sizeof(buf), "Unknown type %d", type);
  }
  info_obj_add_str(express_obj, "type", buf);
  info_obj_add_fmt_buf_str(express_obj, "MSI", buf, sizeof(buf), "%02x", (cap & PCI_EXP_FLAGS_IRQ) >> 9);

  if (verbose < 2)
    return type;

  size = 16;
  if (slot)
    size = 24;
  if (type == PCI_EXP_TYPE_ROOT_PORT)
    size = 32;
  if (!config_fetch(d, where + PCI_EXP_DEVCAP, size))
    return type;

  fill_info_express_dev(express_obj, d, where, type);
  if (link)
    fill_info_express_link(express_obj, d, where, type);
  if (slot)
    fill_info_express_slot(express_obj, d, where);
  if (type == PCI_EXP_TYPE_ROOT_PORT)
    fill_info_express_root(express_obj, d, where);

  if ((cap & PCI_EXP_FLAGS_VERS) < 2)
    return type;

  size = 16;
  if (slot)
    size = 24;
  if (!config_fetch(d, where + PCI_EXP_DEVCAP2, size))
    return type;

  fill_info_express_dev2(express_obj, d, where, type);
  if (link)
    fill_info_express_link2(express_obj, d, where, type);

  return type;
}

static void
cap_msix(struct device *d, int where, int cap)
{
  u32 off;

  printf("MSI-X: Enable%c Count=%d Masked%c\n",
	 FLAG(cap, PCI_MSIX_ENABLE),
	 (cap & PCI_MSIX_TABSIZE) + 1,
	 FLAG(cap, PCI_MSIX_MASK));
  if (verbose < 2 || !config_fetch(d, where + PCI_MSIX_TABLE, 8))
    return;

  off = get_conf_long(d, where + PCI_MSIX_TABLE);
  printf("\t\tVector table: BAR=%d offset=%08x\n",
	 off & PCI_MSIX_BIR, off & ~PCI_MSIX_BIR);
  off = get_conf_long(d, where + PCI_MSIX_PBA);
  printf("\t\tPBA: BAR=%d offset=%08x\n",
	 off & PCI_MSIX_BIR, off & ~PCI_MSIX_BIR);
}

static void
cap_slotid(int cap)
{
  int esr = cap & 0xff;
  int chs = cap >> 8;

  printf("Slot ID: %d slots, First%c, chassis %02x\n",
	 esr & PCI_SID_ESR_NSLOTS,
	 FLAG(esr, PCI_SID_ESR_FIC),
	 chs);
}

static void
cap_ssvid(struct device *d, int where)
{
  u16 subsys_v, subsys_d;
  char ssnamebuf[256];

  if (!config_fetch(d, where, 8))
    return;
  subsys_v = get_conf_word(d, where + PCI_SSVID_VENDOR);
  subsys_d = get_conf_word(d, where + PCI_SSVID_DEVICE);
  printf("Subsystem: %s\n",
	   pci_lookup_name(pacc, ssnamebuf, sizeof(ssnamebuf),
			   PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
			   d->dev->vendor_id, d->dev->device_id, subsys_v, subsys_d));
}

static void
fill_info_cap_ssvid(struct info_obj *caps_obj, struct device *d, int where)
{
  u16 subsys_v, subsys_d;
  char ssnamebuf[256];
  struct info_obj *ssvid_obj = info_obj_create_in_obj(caps_obj, "Subsystem");

  if (!config_fetch(d, where, 8))
    return;
  subsys_v = get_conf_word(d, where + PCI_SSVID_VENDOR);
  subsys_d = get_conf_word(d, where + PCI_SSVID_DEVICE);

  info_obj_add_str(ssvid_obj, "Subsystem", pci_lookup_name(pacc, ssnamebuf, sizeof(ssnamebuf),
	  PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
	  d->dev->vendor_id, d->dev->device_id, subsys_v, subsys_d));
}

static void
cap_debug_port(int cap)
{
  int bar = cap >> 13;
  int pos = cap & 0x1fff;
  printf("Debug port: BAR=%d offset=%04x\n", bar, pos);
}

static void
fill_info_cap_debug_port(struct info_obj *caps_obj, int cap)
{
  int bar = cap >> 13;
  int pos = cap & 0x1fff;
  struct info_obj *dbg_port_obj = info_obj_create_in_obj(caps_obj, "Debug port");
  char buf[32];

  info_obj_add_fmt_buf_str(dbg_port_obj, "BAR", buf, sizeof(buf), "%d", bar);
  info_obj_add_fmt_buf_str(dbg_port_obj, "offset", buf, sizeof(buf), "%04x", pos);
}

static void
cap_af(struct device *d, int where)
{
  u8 reg;

  printf("PCI Advanced Features\n");
  if (verbose < 2 || !config_fetch(d, where + PCI_AF_CAP, 3))
    return;

  reg = get_conf_byte(d, where + PCI_AF_CAP);
  printf("\t\tAFCap: TP%c FLR%c\n", FLAG(reg, PCI_AF_CAP_TP),
	 FLAG(reg, PCI_AF_CAP_FLR));
  reg = get_conf_byte(d, where + PCI_AF_CTRL);
  printf("\t\tAFCtrl: FLR%c\n", FLAG(reg, PCI_AF_CTRL_FLR));
  reg = get_conf_byte(d, where + PCI_AF_STATUS);
  printf("\t\tAFStatus: TP%c\n", FLAG(reg, PCI_AF_STATUS_TP));
}

static void
cap_sata_hba(struct device *d, int where, int cap)
{
  u32 bars;
  int bar;

  printf("SATA HBA v%d.%d", BITS(cap, 4, 4), BITS(cap, 0, 4));
  if (verbose < 2 || !config_fetch(d, where + PCI_SATA_HBA_BARS, 4))
    {
      printf("\n");
      return;
    }

  bars = get_conf_long(d, where + PCI_SATA_HBA_BARS);
  bar = BITS(bars, 0, 4);
  if (bar >= 4 && bar <= 9)
    printf(" BAR%d Offset=%08x\n", bar - 4, BITS(bars, 4, 20));
  else if (bar == 15)
    printf(" InCfgSpace\n");
  else
    printf(" BAR??%d\n", bar);
}

static const char *cap_ea_property(int p, int is_secondary)
{
  switch (p) {
  case 0x00:
    return "memory space, non-prefetchable";
  case 0x01:
    return "memory space, prefetchable";
  case 0x02:
    return "I/O space";
  case 0x03:
    return "VF memory space, prefetchable";
  case 0x04:
    return "VF memory space, non-prefetchable";
  case 0x05:
    return "allocation behind bridge, non-prefetchable memory";
  case 0x06:
    return "allocation behind bridge, prefetchable memory";
  case 0x07:
    return "allocation behind bridge, I/O space";
  case 0xfd:
    return "memory space resource unavailable for use";
  case 0xfe:
    return "I/O space resource unavailable for use";
  case 0xff:
    if (is_secondary)
      return "entry unavailable for use, PrimaryProperties should be used";
    else
      return "entry unavailable for use";
  default:
    return NULL;
  }
}

static void cap_ea(struct device *d, int where, int cap)
{
  int entry;
  int entry_base = where + 4;
  int num_entries = BITS(cap, 0, 6);
  u8 htype = get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f;

  printf("Enhanced Allocation (EA): NumEntries=%u", num_entries);
  if (htype == PCI_HEADER_TYPE_BRIDGE) {
    byte fixed_sub, fixed_sec;

    entry_base += 4;
    if (!config_fetch(d, where + 4, 2)) {
      printf("\n");
      return;
    }
    fixed_sec = get_conf_byte(d, where + PCI_EA_CAP_TYPE1_SECONDARY);
    fixed_sub = get_conf_byte(d, where + PCI_EA_CAP_TYPE1_SUBORDINATE);
    printf(", secondary=%d, subordinate=%d", fixed_sec, fixed_sub);
  }
  printf("\n");
  if (verbose < 2)
    return;

  for (entry = 0; entry < num_entries; entry++) {
    int max_offset_high_pos, has_base_high, has_max_offset_high;
    u32 entry_header;
    u32 base, max_offset;
    int es, bei, pp, sp;
    const char *prop_text;

    if (!config_fetch(d, entry_base, 4))
      return;
    entry_header = get_conf_long(d, entry_base);
    es = BITS(entry_header, 0, 3);
    bei = BITS(entry_header, 4, 4);
    pp = BITS(entry_header, 8, 8);
    sp = BITS(entry_header, 16, 8);
    if (!config_fetch(d, entry_base + 4, es * 4))
      return;
    printf("\t\tEntry %u: Enable%c Writable%c EntrySize=%u\n", entry,
	   FLAG(entry_header, PCI_EA_CAP_ENT_ENABLE),
	   FLAG(entry_header, PCI_EA_CAP_ENT_WRITABLE), es);
    printf("\t\t\t BAR Equivalent Indicator: ");
    switch (bei) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
      printf("BAR %u", bei);
      break;
    case 6:
      printf("resource behind function");
      break;
    case 7:
      printf("not indicated");
      break;
    case 8:
      printf("expansion ROM");
      break;
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
      printf("VF-BAR %u", bei - 9);
      break;
    default:
      printf("reserved");
      break;
    }
    printf("\n");

    prop_text = cap_ea_property(pp, 0);
    printf("\t\t\t PrimaryProperties: ");
    if (prop_text)
      printf("%s\n", prop_text);
    else
      printf("[%02x]\n", pp);

    prop_text = cap_ea_property(sp, 1);
    printf("\t\t\t SecondaryProperties: ");
    if (prop_text)
      printf("%s\n", prop_text);
    else
      printf("[%02x]\n", sp);

    base = get_conf_long(d, entry_base + 4);
    has_base_high = ((base & 2) != 0);
    base &= ~3;

    max_offset = get_conf_long(d, entry_base + 8);
    has_max_offset_high = ((max_offset & 2) != 0);
    max_offset |= 3;
    max_offset_high_pos = entry_base + 12;

    printf("\t\t\t Base: ");
    if (has_base_high) {
      u32 base_high = get_conf_long(d, entry_base + 12);

      printf("%x", base_high);
      max_offset_high_pos += 4;
    }
    printf("%08x\n", base);

    printf("\t\t\t MaxOffset: ");
    if (has_max_offset_high) {
      u32 max_offset_high = get_conf_long(d, max_offset_high_pos);

      printf("%x", max_offset_high);
    }
    printf("%08x\n", max_offset);

    entry_base += 4 + 4 * es;
  }
}

void
show_caps(struct device *d, int where)
{
  int can_have_ext_caps = 0;
  int type = -1;

  if (get_conf_word(d, PCI_STATUS) & PCI_STATUS_CAP_LIST)
    {
      byte been_there[256];
      where = get_conf_byte(d, where) & ~3;
      memset(been_there, 0, 256);
      while (where)
	{
	  int id, next, cap;
	  printf("\tCapabilities: ");
	  if (!config_fetch(d, where, 4))
	    {
	      puts("<access denied>");
	      break;
	    }
	  id = get_conf_byte(d, where + PCI_CAP_LIST_ID);
	  next = get_conf_byte(d, where + PCI_CAP_LIST_NEXT) & ~3;
	  cap = get_conf_word(d, where + PCI_CAP_FLAGS);
	  printf("[%02x] ", where);
	  if (been_there[where]++)
	    {
	      printf("<chain looped>\n");
	      break;
	    }
	  if (id == 0xff)
	    {
	      printf("<chain broken>\n");
	      break;
	    }
	  switch (id)
	    {
	    case PCI_CAP_ID_PM:
	      cap_pm(d, where, cap);
	      break;
	    case PCI_CAP_ID_AGP:
	      cap_agp(d, where, cap);
	      break;
	    case PCI_CAP_ID_VPD:
	      cap_vpd(d);
	      break;
	    case PCI_CAP_ID_SLOTID:
	      cap_slotid(cap);
	      break;
	    case PCI_CAP_ID_MSI:
	      cap_msi(d, where, cap);
	      break;
	    case PCI_CAP_ID_CHSWP:
	      printf("CompactPCI hot-swap <?>\n");
	      break;
	    case PCI_CAP_ID_PCIX:
	      cap_pcix(d, where);
	      can_have_ext_caps = 1;
	      break;
	    case PCI_CAP_ID_HT:
	      cap_ht(d, where, cap);
	      break;
	    case PCI_CAP_ID_VNDR:
	      show_vendor_caps(d, where, cap);
	      break;
	    case PCI_CAP_ID_DBG:
	      cap_debug_port(cap);
	      break;
	    case PCI_CAP_ID_CCRC:
	      printf("CompactPCI central resource control <?>\n");
	      break;
	    case PCI_CAP_ID_HOTPLUG:
	      printf("Hot-plug capable\n");
	      break;
	    case PCI_CAP_ID_SSVID:
	      cap_ssvid(d, where);
	      break;
	    case PCI_CAP_ID_AGP3:
	      printf("AGP3 <?>\n");
	      break;
	    case PCI_CAP_ID_SECURE:
	      printf("Secure device <?>\n");
	      break;
	    case PCI_CAP_ID_EXP:
	      type = cap_express(d, where, cap);
	      can_have_ext_caps = 1;
	      break;
	    case PCI_CAP_ID_MSIX:
	      cap_msix(d, where, cap);
	      break;
	    case PCI_CAP_ID_SATA:
	      cap_sata_hba(d, where, cap);
	      break;
	    case PCI_CAP_ID_AF:
	      cap_af(d, where);
	      break;
	    case PCI_CAP_ID_EA:
	      cap_ea(d, where, cap);
	      break;
	    default:
	      printf("#%02x [%04x]\n", id, cap);
	    }
	  where = next;
	}
    }
  if (can_have_ext_caps)
    show_ext_caps(d, type);
}

void
fill_info_caps(struct info_obj *dev_obj, struct device *d, int where)
{
  struct info_obj *caps_obj = info_obj_create_in_obj(dev_obj, "capabilities");

  if (get_conf_word(d, PCI_STATUS) & PCI_STATUS_CAP_LIST)
    {
      byte been_there[256];
      where = get_conf_byte(d, where) & ~3;
      memset(been_there, 0, 256);
      while (where)
	{
	  int id, next, cap;
	  if (!config_fetch(d, where, 4))
	    {
	      fputs("<access denied>", stderr);
	      break;
	    }
	  id = get_conf_byte(d, where + PCI_CAP_LIST_ID);
	  next = get_conf_byte(d, where + PCI_CAP_LIST_NEXT) & ~3;
	  cap = get_conf_word(d, where + PCI_CAP_FLAGS);
	  if (been_there[where]++)
	    {
	      fprintf(stderr, "<chain looped>\n");
	      break;
	    }
	  if (id == 0xff)
	    {
	      fprintf(stderr, "<chain broken>\n");
	      break;
	    }
	  switch (id)
	    {
	    case PCI_CAP_ID_PM:
	      fill_info_cap_pm(caps_obj, d, where, cap);
	      break;
	    case PCI_CAP_ID_EXP:
	      fill_info_cap_express(caps_obj, d, where, cap);
	      break;
	    case PCI_CAP_ID_MSI:
	      fill_info_cap_msi(caps_obj, d, where, cap);
	      break;
	    case PCI_CAP_ID_DBG:
	      fill_info_cap_debug_port(caps_obj, cap);
	      break;
	    case PCI_CAP_ID_SSVID:
	      fill_info_cap_ssvid(caps_obj, d, where);
	      break;
	    default:
	      break;
	    }
	  where = next;
	}
    }
}
