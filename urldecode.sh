#!/bin/bash
# urldecode <string>
url_encoded="${*//+/ }"
printf '%b' "${url_encoded//%/\\x}"
