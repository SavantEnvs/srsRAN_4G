#include "common.h"
#include "srsran/common/byte_buffer.h"
#include "srsran/mac/mac_rar_pdu_nr.h"
#include "srsran/mac/mac_sch_pdu_nr.h"

#include <cstring>
#include <memory>

using namespace srsran;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  mayhem_quiet_logs();
  return 0;
}

static int sch(const uint8_t* pdu, uint32_t len, bool ulsch)
{
  mac_sch_pdu_nr sch_pdu(ulsch);
  int            ret = sch_pdu.unpack(pdu, len);
  for (uint32_t i = 0; i < sch_pdu.get_num_subpdus(); ++i) {
    const mac_sch_subpdu_nr& sub = sch_pdu.get_subpdu(i);
    (void)sub.get_lcid();
    (void)sub.get_sdu_length();
  }
  fmt::memory_buffer buffer;
  sch_pdu.to_string(buffer);
  return ret == SRSRAN_SUCCESS ? 0 : -1;
}

static int rar(const uint8_t* pdu, uint32_t len)
{
  mac_rar_pdu_nr rar_pdu;
  bool           ok = rar_pdu.unpack(pdu, len);
  fmt::memory_buffer buffer;
  rar_pdu.to_string(buffer);
  return ok ? 0 : -1;
}

// Input: one byte selecting the MAC PDU kind (0 DL-SCH, 1 UL-SCH, 2 RAR), then the PDU bytes.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 2) {
    return -1;
  }
  const uint32_t len = size - 1;
  // MAC PDUs are received into a byte_buffer_t; the subheader parser reads ahead of the PDU length without
  // checking it, so keep the PDU in a zero-filled array of that capacity.
  if (len > SRSRAN_MAX_BUFFER_SIZE_BYTES - SRSRAN_BUFFER_HEADER_OFFSET) {
    return -1;
  }
  std::unique_ptr<uint8_t[]> pdu(new uint8_t[SRSRAN_MAX_BUFFER_SIZE_BYTES]());
  memcpy(pdu.get(), data + 1, len);
  switch (data[0] % 3) {
    case 0:
      return sch(pdu.get(), len, false);
    case 1:
      return sch(pdu.get(), len, true);
    default:
      return rar(pdu.get(), len);
  }
}
