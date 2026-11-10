# mobile_identity_5gs_t::suci_s::unpack: unbounded allocation from an underflowed length

- Reproduce: `ASAN_OPTIONS=allocator_may_return_null=0:max_allocation_size_mb=500 /mayhem/fuzz_nas_5g-standalone mayhem/fuzz_nas_5g/known-findings/suci-length-underflow-alloc/input` (libFuzzer reports it as out-of-memory)
- Cause: `lib/src/asn1/nas_5g_ies.cc:280` does `scheme_output.resize(length - 8)` with `length` the 16-bit mobile-identity length from the message; a length below 8 wraps to a ~4 GiB `std::vector<uint8_t>` allocation (0xfffffff8 bytes).
- Impact: remote memory exhaustion / allocation failure while decoding a 5GS NAS message that carries a SUCI mobile identity (Identity Response, Registration Request, ...).
- Fix: fail the unpack when `length < 8`, before resizing.
