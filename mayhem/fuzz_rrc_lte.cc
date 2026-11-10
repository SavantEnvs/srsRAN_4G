#include "common.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/rrc.h"

using namespace asn1;
using namespace asn1::rrc;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  mayhem_quiet_logs();
  return 0;
}

template <typename Msg>
static int decode(const uint8_t* data, size_t size)
{
  Msg      msg;
  cbit_ref bref(data, size);
  if (msg.unpack(bref) != SRSASN_SUCCESS) {
    return -1;
  }
  json_writer jw;
  msg.to_json(jw);
  return 0;
}

// Input: one byte selecting the RRC logical channel, then the PDU bytes.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1) {
    return -1;
  }
  const uint8_t* pdu     = data + 1;
  const size_t   pdu_len = size - 1;
  switch (data[0] % 8) {
    case 0:
      return decode<dl_ccch_msg_s>(pdu, pdu_len);
    case 1:
      return decode<dl_dcch_msg_s>(pdu, pdu_len);
    case 2:
      return decode<ul_ccch_msg_s>(pdu, pdu_len);
    case 3:
      return decode<ul_dcch_msg_s>(pdu, pdu_len);
    case 4:
      return decode<bcch_bch_msg_s>(pdu, pdu_len);
    case 5:
      return decode<bcch_dl_sch_msg_s>(pdu, pdu_len);
    case 6:
      return decode<pcch_msg_s>(pdu, pdu_len);
    default:
      return decode<mcch_msg_s>(pdu, pdu_len);
  }
}
