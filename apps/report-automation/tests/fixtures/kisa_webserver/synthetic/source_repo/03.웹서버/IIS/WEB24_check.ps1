# Synthetic fixture for tests only.
# @ID: WEB-24
# @Title: IIS Request Filtering Configuration
# @Severity: 상
# @Reference: KISA-WS-IIS-WEB24
$ITEM_ID = "WEB-24"
$ITEM_NAME = "IIS Request Filtering Configuration"
$SEVERITY = "상"
$REFERENCE = "KISA-WS-IIS-WEB24"
$purpose = "web.config 와 Request Filtering 정책 확인"
Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/security/requestFiltering
