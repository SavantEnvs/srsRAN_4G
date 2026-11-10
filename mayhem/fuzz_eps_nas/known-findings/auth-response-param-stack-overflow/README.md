# liblte_mme_unpack_authentication_response_parameter_ie: stack-buffer-overflow

- Reproduce: `/mayhem/fuzz_eps_nas-standalone mayhem/fuzz_eps_nas/known-findings/auth-response-param-stack-overflow/input`
- Cause: `lib/src/asn1/liblte_mme.cc:933` copies `(*ie_ptr)[0]` (a 0..255 length byte read from the wire) bytes into the caller's `res` array, which is only 16 bytes (`LIBLTE_MME_AUTHENTICATION_RESPONSE_PARAMETER_STRUCT.res`), so a length above 16 overflows the stack.
- Impact: remote stack write of up to 239 attacker-controlled bytes while decoding an EPS NAS Authentication Response.
- Fix: reject a length greater than the size of `res` before the copy loop.
