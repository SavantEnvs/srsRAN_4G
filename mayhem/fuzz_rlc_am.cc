#include "common.h"
#include "srsran/common/byte_buffer.h"
#include "srsran/rlc/rlc_am_lte_packing.h"
#include "srsran/rlc/rlc_am_nr_packing.h"

#include <cstring>
#include <memory>

using namespace srsran;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  mayhem_quiet_logs();
  return 0;
}

// Input: one byte selecting the parser, then the RLC PDU as received from MAC.
//   0 LTE status PDU, 1 LTE data header, 2/3 NR status PDU (12/18-bit SN), 4/5 NR data header (12/18-bit SN)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  // An RLC PDU is handed to these parsers inside a byte_buffer_t, so it is never larger than its capacity.
  constexpr size_t max_pdu = SRSRAN_MAX_BUFFER_SIZE_BYTES - SRSRAN_BUFFER_HEADER_OFFSET;
  if (size < 2 || size - 1 > max_pdu) {
    return -1;
  }
  const uint32_t pdu_len = size - 1;
  // The PDU sits in a zero-filled byte_buffer_t-sized array, as on the receive path: the parsers read a few
  // bytes ahead of the length they are given without checking it.
  std::unique_ptr<uint8_t[]> buf(new uint8_t[SRSRAN_MAX_BUFFER_SIZE_BYTES]());
  uint8_t*                   pdu = buf.get();
  memcpy(pdu, data + 1, pdu_len);

  switch (data[0] % 6) {
    case 0: {
      auto status = std::make_unique<rlc_status_pdu_t>();
      rlc_am_read_status_pdu(pdu, pdu_len, status.get());
      rlc_am_is_valid_status_pdu(*status);
      return 0;
    }
    case 1: {
      rlc_amd_pdu_header_t header;
      uint8_t*             p = pdu;
      uint32_t             n = pdu_len;
      rlc_am_read_data_pdu_header(&p, &n, &header);
      rlc_am_is_pdu_segment(pdu);
      return 0;
    }
    case 2:
    case 3: {
      rlc_am_nr_sn_size_t    sn = data[0] % 6 == 2 ? rlc_am_nr_sn_size_t::size12bits : rlc_am_nr_sn_size_t::size18bits;
      rlc_am_nr_status_pdu_t status(sn);
      // Returns 0 for both success and malformed input, so there is no reject signal.
      rlc_am_nr_read_status_pdu(pdu, pdu_len, sn, &status);
      return 0;
    }
    default: {
      rlc_am_nr_sn_size_t    sn = data[0] % 6 == 4 ? rlc_am_nr_sn_size_t::size12bits : rlc_am_nr_sn_size_t::size18bits;
      rlc_am_nr_pdu_header_t header;
      return rlc_am_nr_read_data_pdu_header(pdu, pdu_len, sn, &header) == 0 ? -1 : 0;
    }
  }
}
