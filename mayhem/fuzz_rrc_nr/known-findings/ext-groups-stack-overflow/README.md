# ext_groups_unpacker_guard::~ext_groups_unpacker_guard: stack-buffer-overflow (NR RRC)

Same signature as `mayhem/fuzz_rrc_lte/known-findings/ext-groups-stack-overflow/`, reached through an NR RRC message.

- Reproduce: `/mayhem/fuzz_rrc_nr-standalone mayhem/fuzz_rrc_nr/known-findings/ext-groups-stack-overflow/input`
- Observed: ASan stack-buffer-overflow read at `lib/src/asn1/asn1_utils.cc:1377` in the destructor.
- Fix direction: see the LTE entry.
