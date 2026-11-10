#include "common.h"
#include "srsran/asn1/nas_5g_msg.h"

#include <vector>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  mayhem_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  std::vector<uint8_t> buf(data, data + size);
  srsran::nas_5g::nas_5gs_msg msg;
  if (msg.unpack(buf) != SRSASN_SUCCESS) {
    return -1;
  }
  return 0;
}
