#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-26
# @Title: Apache Suspicious Script Scan
# @Severity: 상
# @Reference: KISA-WS-APACHE-WEB26
ITEM_ID="WEB-26"
ITEM_NAME="Apache Suspicious Script Scan"
SEVERITY="상"
REFERENCE="KISA-WS-APACHE-WEB26"
find /var/www/html -name "*.php" -print
