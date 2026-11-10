# rlc_am_read_data_pdu_header (LTE): stack-buffer-overflow in the length-indicator loop

- Reproduce: `/mayhem/fuzz_rlc_am-standalone mayhem/fuzz_rlc_am/known-findings/lte-data-header-stack-overflow/input` (first byte selects the parser: 1 = LTE data header)
- Cause: `lib/src/rlc/rlc_am_lte_packing.cc:54` keeps reading 12-bit LIs while the E bit is set and stores each into `header->li[header->N_li]`, a fixed array (`RLC_AM_WINDOW_SIZE`-bounded), with no bound on `N_li` and no check against `nof_bytes`.
- Impact: stack overflow of the parsed header (and read past the PDU) from a crafted AMD PDU.
- Fix: stop at `nof_bytes` and cap `N_li` at the array size, returning an error.
