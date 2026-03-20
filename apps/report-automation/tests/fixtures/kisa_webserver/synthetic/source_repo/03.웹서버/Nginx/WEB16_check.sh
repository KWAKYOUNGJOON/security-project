#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-16
# @Title: Nginx Access Log Retention
# @Severity: 상
# @Reference: KISA-WS-NGINX-WEB16
ITEM_ID="WEB-16"
ITEM_NAME="Nginx Access Log Retention"
SEVERITY="하"
REFERENCE="KISA-WS-NGINX-WEB16"
GUIDELINE_PURPOSE="로그 보관 정책 확인"
grep -n "access_log" /etc/nginx/nginx.conf
