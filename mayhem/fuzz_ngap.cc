#include "common.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/ngap.h"

using namespace asn1;
using namespace asn1::ngap;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  mayhem_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  ngap_pdu_c pdu;
  cbit_ref   bref(data, size);
  if (pdu.unpack(bref) != SRSASN_SUCCESS) {
    return -1;
  }
  json_writer jw;
  pdu.to_json(jw);
  return 0;
}
