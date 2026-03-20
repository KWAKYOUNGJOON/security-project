#!/bin/sh
# Synthetic fixture for tests only.
# @ID: WEB-24
# @Title: Tomcat AJP Configuration
# @Severity: 상
# @Reference: KISA-WS-TOMCAT-WEB24
ITEM_ID="WEB-24"
ITEM_NAME="Tomcat AJP Configuration"
SEVERITY="상"
REFERENCE="KISA-WS-TOMCAT-WEB24"
grep -n "Connector port=\"8009\"" /usr/local/tomcat/conf/server.xml
