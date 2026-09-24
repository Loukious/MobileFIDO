#!/system/bin/sh
# Read-only APK Signing Block signer-certificate extraction for module install.
# The build host performs full cryptographic verification with Android SDK
# apksigner. This helper identifies the signer of PackageManager-installed APKs
# without relying on dumpsys' weak 32-bit Signature.hashCode.

native_read_u32() {
    dd if="$1" bs=1 skip="$2" count=4 2>/dev/null | od -An -tu4 | tr -d ' \r\n'
}

native_read_u64_small() {
    native_lo="$(native_read_u32 "$1" "$2")"
    native_hi="$(native_read_u32 "$1" $(( $2 + 4 )))"
    [ -n "$native_lo" ] && [ "$native_hi" = 0 ] || return 1
    printf '%s\n' "$native_lo"
}

native_read_hex4() {
    dd if="$1" bs=1 skip="$2" count=4 2>/dev/null | od -An -tx4 | tr -d ' \r\n'
}

native_read_hex() {
    dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | od -An -tx1 | tr -d ' \r\n'
}

native_apk_signer_sha256() {
    native_apk="$1"
    [ -f "$native_apk" ] || return 1
    native_size="$(wc -c < "$native_apk" | tr -d ' \r\n')"
    case "$native_size" in ''|*[!0-9]*) return 1 ;; esac
    [ "$native_size" -ge 46 ] || return 1
    native_eocd=$((native_size - 22))
    [ "$(native_read_hex "$native_apk" "$native_eocd" 4)" = 504b0506 ] || return 1
    # MobileFIDO's canonical release APK has no ZIP comment. Reject a shape we
    # do not deliberately build instead of scanning ambiguous EOCD candidates.
    [ "$(native_read_hex "$native_apk" $((native_eocd + 20)) 2)" = 0000 ] || return 1
    native_cd="$(native_read_u32 "$native_apk" $((native_eocd + 16)))"
    case "$native_cd" in ''|*[!0-9]*) return 1 ;; esac
    [ "$native_cd" -ge 24 ] && [ "$native_cd" -le "$native_eocd" ] || return 1
    [ "$(native_read_hex "$native_apk" $((native_cd - 16)) 16)" = \
        41504b2053696720426c6f636b203432 ] || return 1
    native_block_size="$(native_read_u64_small "$native_apk" $((native_cd - 24)))" || return 1
    native_start=$((native_cd - native_block_size - 8))
    [ "$native_start" -ge 0 ] || return 1
    [ "$(native_read_u64_small "$native_apk" "$native_start")" = "$native_block_size" ] || return 1

    native_pos=$((native_start + 8))
    native_pairs_end=$((native_cd - 24))
    native_scheme_start=
    native_scheme_end=
    native_scheme_rank=0
    while [ "$native_pos" -lt "$native_pairs_end" ]; do
        native_pair_len="$(native_read_u64_small "$native_apk" "$native_pos")" || return 1
        case "$native_pair_len" in ''|*[!0-9]*) return 1 ;; esac
        [ "$native_pair_len" -ge 4 ] || return 1
        native_pair_end=$((native_pos + 8 + native_pair_len))
        [ "$native_pair_end" -le "$native_pairs_end" ] || return 1
        native_id="$(native_read_hex4 "$native_apk" $((native_pos + 8)))"
        native_rank=0
        case "$native_id" in
            1b93ad61) native_rank=3 ;; # APK Signature Scheme v3.1
            f05368c0) native_rank=2 ;; # APK Signature Scheme v3
            7109871a) native_rank=1 ;; # APK Signature Scheme v2
        esac
        if [ "$native_rank" -gt "$native_scheme_rank" ]; then
            native_scheme_rank="$native_rank"
            native_scheme_start=$((native_pos + 12))
            native_scheme_end="$native_pair_end"
        fi
        native_pos="$native_pair_end"
    done
    [ "$native_pos" -eq "$native_pairs_end" ] && [ "$native_scheme_rank" -gt 0 ] || return 1

    native_outer_len="$(native_read_u32 "$native_apk" "$native_scheme_start")"
    native_signer_at=$((native_scheme_start + 4))
    native_signer_len="$(native_read_u32 "$native_apk" "$native_signer_at")"
    case "$native_outer_len:$native_signer_len" in *[!0-9:]*) return 1 ;; esac
    # Exactly one signer: outer sequence is exactly one length-prefixed signer.
    [ "$native_outer_len" -eq $((native_signer_len + 4)) ] || return 1
    [ $((native_scheme_start + 4 + native_outer_len)) -eq "$native_scheme_end" ] || return 1
    native_signer_content=$((native_signer_at + 4))
    native_signed_len="$(native_read_u32 "$native_apk" "$native_signer_content")"
    native_signed_start=$((native_signer_content + 4))
    native_signed_end=$((native_signed_start + native_signed_len))
    [ "$native_signed_end" -le "$native_scheme_end" ] || return 1
    native_digests_len="$(native_read_u32 "$native_apk" "$native_signed_start")"
    native_certs_len_at=$((native_signed_start + 4 + native_digests_len))
    [ "$native_certs_len_at" -lt "$native_signed_end" ] || return 1
    native_certs_len="$(native_read_u32 "$native_apk" "$native_certs_len_at")"
    native_certs_start=$((native_certs_len_at + 4))
    native_certs_end=$((native_certs_start + native_certs_len))
    [ "$native_certs_end" -le "$native_signed_end" ] || return 1
    native_cert_len="$(native_read_u32 "$native_apk" "$native_certs_start")"
    native_cert_start=$((native_certs_start + 4))
    [ "$native_cert_len" -gt 0 ] && [ $((native_cert_start + native_cert_len)) -le "$native_certs_end" ] || return 1
    dd if="$native_apk" bs=1 skip="$native_cert_start" count="$native_cert_len" 2>/dev/null |
        sha256sum | cut -d ' ' -f 1
}
