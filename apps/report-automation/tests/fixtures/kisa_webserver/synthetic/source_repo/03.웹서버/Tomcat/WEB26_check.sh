#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-26
# @Title: Tomcat Manager Exposure
# @Severity: 상
ITEM_ID="WEB-26"
ITEM_NAME="Tomcat Manager Exposure"
SEVERITY="상"
grep -n "<user username=\"tomcat\"" /usr/local/tomcat/conf/tomcat-users.xml
