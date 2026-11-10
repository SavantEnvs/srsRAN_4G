#include "common.h"
#include "srsran/common/byte_buffer.h"
#include "srsran/upper/gtpu.h"

#include <cstring>
#include <memory>

using namespace srsran;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  mayhem_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  // GTP-U PDUs are received into a byte_buffer_t, so they cannot exceed its capacity.
  if (size > SRSRAN_MAX_BUFFER_SIZE_BYTES - SRSRAN_BUFFER_HEADER_OFFSET) {
    return -1;
  }
  auto pdu = std::make_unique<byte_buffer_t>();
  if (size > 0) {
    memcpy(pdu->msg, data, size);
  }
  pdu->N_bytes = size;

  gtpu_header_t header;
  return gtpu_read_header(pdu.get(), &header, srslog::fetch_basic_logger("GTPU")) ? 0 : -1;
}
