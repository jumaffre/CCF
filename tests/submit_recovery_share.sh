#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e


# TODO: Why is --rpc-address passed in? Cannot use https:// instead?
# Because of the method/verb!
function usage()
{
    echo "Usage:"""
    echo "  $0 --rpc-address rpc_address --member-enc-privk member_enc_privk.pem --network-enc-pubk network_enc_pubk.pem [CURL_OPTIONS]"
    echo "Retrieves the encrypted recovery share for a given member, decrypts the share and submits it for recovery."
    echo ""
    echo "A sufficient number of recovery shares must be submitted by members to initiate the end of recovery procedure."
    echo "Note: Requires step CLI."
}

while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        --rpc-address)
            node_rpc_address="$2"
            ;;
        --member-enc-privk)
            member_enc_privk="$2"
            ;;
        --network-enc-pubk)
            network_enc_pubk="$2"
            ;;
        *)
            break
    esac
    shift
    shift
done

if ! [ -x "$(command -v step)" ]; then
    echo "Error: step CLI is not installed on your system or not in your path."
    echo "See https://microsoft.github.io/CCF/master/members/accept_recovery.html#submitting-recovery-shares"
    exit 1
fi

if [ -z "$node_rpc_address" ]; then
    echo "Error: No node RPC address in arguments (--rpc-address)"
    exit 1
fi

if [ -z "$member_enc_privk" ]; then
    echo "Error: No member encryption private key in arguments (--member-enc-privk)"
    exit 1
fi

if [ -z "$network_enc_pubk" ]; then
    echo "Error: No defunct network encryption public key in arguments (--network-enc-pubk)"
    exit 1
fi

# TODO: Check for errors, probably using ||

# set -x
# Retrieve encrypted recovery share and nonce
resp=$(curl -sS https://${node_rpc_address}/members/getEncryptedRecoveryShare ${@})
encrypted_share="$(echo ${resp} | jq -r .encrypted_recovery_share)"
nonce="$(echo ${resp} | jq -r .nonce)"

# echo "Encrypted recovery share: ${encrypted_share}"
# echo "Nonce: ${nonce}"

# Parse raw private key from SubjectPublicKeyInfo DER format, as generated by keygenerator.sh --gen-enc-key
der_header_privk_len=14
openssl asn1parse -in ${member_enc_privk} -strparse ${der_header_privk_len} -out key.raw -noout

# # Parse raw public key generated by network
der_header_pubk_len=9
openssl asn1parse -in ${network_enc_pubk} -i -strparse ${der_header_pubk_len} -out key2.raw -noout

# step Base64 standard to URL encoding
encrypted_share_b64_url=$(echo ${encrypted_share} | sed 's/+/-/g; s/\//_/g')

# Decrypt encrypted share with nonce, member private key and previous network public key
decrypted_share=$(echo "${encrypted_share_b64_url}" | step crypto nacl box open base64:"${nonce}" key2.raw key.raw | openssl base64 -A)

# Finally. submit encrypted share
curl https://${node_rpc_address}/members/submitRecoveryShare ${@} -H "Content-Type: application/json" -d '{"recovery_share": "'${decrypted_share}'"}'