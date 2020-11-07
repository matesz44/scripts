#!/bin/sh

# jwtdec.sh -j [JWT_enc]
# jwtdec.sh -j [JWT_enc] -h [HEADER_dec] -p [PAYLOAD_dec]

for arg in "$@"
do
    case $arg in
        --hh) echo "Usage: jwtdec.sh -j [JWT_enc] -h [HEADER_dec] -p [PAYLOAD_dec]"; exit 0 ;;
        -j|--jwt) jwt=$2; shift;shift ;;
        -h|--header) header_supp=$2; shift;shift ;;
        -p|--payload) payload_supp=$2; shift;shift ;;
    esac
done

echo "Decoding from -j"
echo $jwt
header=$(echo $jwt | cut -d. -f1)
payload=$(echo $jwt | cut -d. -f2)
signature=$(echo $jwt | cut -d. -f3)

header_dec=$(echo $header | base64 -d 2>/dev/null)
payload_dec=$(echo $payload | base64 -d 2>/dev/null)

echo "$header\n$header_dec"
echo "$payload\n$payload_dec"
echo $signature

echo "------"

echo "Encoding from -h -p"
header_enc=$(echo -n $header_supp | base64 | tr -d '=' | tr -d '\t\r\n')
payload_enc=$(echo -n $payload_supp | base64 | tr -d '=' | tr -d '\t\r\n')
echo "$header_enc\n$header_supp"
echo "---"
echo "$payload_enc\n$payload_supp"
