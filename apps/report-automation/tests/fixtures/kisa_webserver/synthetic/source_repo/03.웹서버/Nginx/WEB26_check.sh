#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-26
# @Title: Nginx Hidden File Exposure
# @Severity: 중
# @Reference: KISA-WS-NGINX-WEB26
ITEM_ID="WEB-26"
ITEM_NAME="Nginx Hidden File Exposure"
SEVERITY="중"
REFERENCE="KISA-WS-NGINX-WEB26"
grep -n "location ~ /\\." /etc/nginx/nginx.conf
