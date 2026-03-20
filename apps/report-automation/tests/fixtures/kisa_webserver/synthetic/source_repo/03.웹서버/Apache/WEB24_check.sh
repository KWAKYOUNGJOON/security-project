#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-24
# @Title: Apache DocumentRoot Access Control
# @Severity: 중
# @Reference: KISA-WS-APACHE-WEB24
ITEM_ID="WEB-24"
ITEM_NAME="Apache DocumentRoot Access Control"
SEVERITY="중"
REFERENCE="KISA-WS-APACHE-WEB24"
grep -n "Require all denied" /etc/apache2/apache2.conf
