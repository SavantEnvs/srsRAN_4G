#pragma once

#include "srsran/srslog/srslog.h"

// The library reports every rejected PDU through srslog; silence it so inputs cost parse time only.
static inline void mayhem_quiet_logs()
{
  static const char* const ids[] = {"ASN1", "MAC", "MAC-NR", "RLC", "COMN", "GTPU", "NAS", "STCK", "POOL"};
  for (const char* id : ids) {
    srslog::fetch_basic_logger(id).set_level(srslog::basic_levels::none);
  }
}
