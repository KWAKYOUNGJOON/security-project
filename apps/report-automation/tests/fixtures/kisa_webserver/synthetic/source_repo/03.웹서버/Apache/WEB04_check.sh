#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-04
# @Title: Apache Directory Listing
# @Severity: 중
# @Reference: KISA-WS-APACHE-WEB04
ITEM_ID="WEB-04"
ITEM_NAME="Apache Directory Listing"
SEVERITY="중"
REFERENCE="KISA-WS-APACHE-WEB04"
GUIDELINE_PURPOSE="Indexes 비활성화 여부 확인"
GUIDELINE_REMEDIATION="Options -Indexes 적용"
grep -E '^\s*Options' /etc/apache2/apache2.conf
