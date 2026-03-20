#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-24
# @Title: Nginx Autoindex Setting
# @Severity: 중
# @Reference: KISA-WS-NGINX-WEB24
ITEM_ID="WEB-24"
ITEM_NAME="Nginx Autoindex Setting"
SEVERITY="중"
REFERENCE="KISA-WS-NGINX-WEB24"
grep -n "autoindex" /etc/nginx/nginx.conf
