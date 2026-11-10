# ext_groups_unpacker_guard::~ext_groups_unpacker_guard: stack-buffer-overflow

- Reproduce: `/mayhem/fuzz_rrc_lte-standalone mayhem/fuzz_rrc_lte/known-findings/ext-groups-stack-overflow/input`
- Observed: ASan reports a stack-buffer-overflow read at `lib/src/asn1/asn1_utils.cc:1377` (`if (groups[i])` in the destructor's "consume all the unknown extensions" loop) while an RRC message whose extension-group count comes from the wire is being decoded.
- Cause: not fully analysed. The destructor indexes `ext_array<bool> groups` by `i < nof_unpacked_groups`, a count decoded from the message by `unpack_norm_small_non_neg_whole_number`, and the array is backed by an in-object small buffer (`ext_array::small_buffer`) that the loop can run past.
- Impact: out-of-bounds stack read while decoding any ASN.1 SEQUENCE with an extension marker from untrusted bytes.
- Fix direction: bound the destructor loop by `groups.size()` and re-check how `ext_array::resize` keeps `head` valid when growing past the small buffer.
