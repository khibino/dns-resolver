#!/bin/sh

setvar_ksk() {
    read ksk_flag ksk_proto ksk_alg ksk_b64 <<EOF
$(dig "$1" DNSKEY +short | egrep '^257' | head -1)
EOF
}

setvar_ds() {
    read ds_tag ds_alg ds_hty ds_hash <<EOF
$(dig "$1" DS +short | head -1)
EOF

}

dnskey_rdata() {
    setvar_ksk "$1"

    /usr/bin/printf "$2"
    /usr/bin/printf "\x01\x01"
    ksk_proto_hex=$(/usr/bin/printf "%02x" ${ksk_proto})
    /usr/bin/printf "\x${ksk_proto_hex}"
    ksk_alg_hex=$(/usr/bin/printf "%02x" ${ksk_alg})
    /usr/bin/printf "\x${ksk_alg_hex}"

    echo -n "$ksk_b64" | base64 -id
}

dnskey_rdata_sum() {
    case "$1" in
        1)
            hash=sha1sum
            ;;
        2)
            hash=sha256sum
            ;;
        *)
            ;;
    esac
    dnskey_rdata "$2" "$3" | $hash | tr /a-f/ /A-F/ | sed 's@ *-$@@'
}

check_ds() {
    domain="$1"

    setvar_ds "$domain"
    rdata_sum=$(dnskey_rdata_sum "$ds_hty" "$domain" "$2")

    ds_hash_fmt=$(echo ${ds_hash} | sed 's@ @@')

    cat <<EOF
Domain : ${domain}
RData sum : $rdata_sum
DS hash   : $ds_hash_fmt
EOF

    if [ "${rdata_sum}" = "${ds_hash_fmt}" ]; then
        echo Good
    else
        echo Bad
    fi
}

check_ds iij.ad.jp. "\x03iij\x02ad\x02jp\x00"
check_ds com. "\x03com\x00"
check_ds net. "\x03net\x00"

check_ds salesforce.com. "\x0Asalesforce\x03com\x00"
