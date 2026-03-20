#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-23
# @Title: Nginx Webshell Heuristic Scan
# @Severity: 상
# @Reference: KISA-WS-NGINX-WEB23
ITEM_ID="WEB-23"
ITEM_NAME="Nginx Webshell Heuristic Scan"
SEVERITY="상"
REFERENCE="KISA-WS-NGINX-WEB23"
GUIDELINE_PURPOSE="웹쉘 의심 파일 탐지"
find /usr/share/nginx/html -name "*.php" -print
echo "heuristic webshell review"
