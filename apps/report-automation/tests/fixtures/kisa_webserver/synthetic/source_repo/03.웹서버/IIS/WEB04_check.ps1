# Synthetic fixture for tests only.
# @ID: WEB-04
# @Title: IIS Directory Browsing
# @Severity: 중
# @Reference: KISA-WS-IIS-WEB04
$ITEM_ID = "WEB-04"
$ITEM_NAME = "IIS Directory Browsing"
$SEVERITY = "중"
$REFERENCE = "KISA-WS-IIS-WEB04"
$purpose = "DirectoryBrowse 비활성화 여부 확인"
Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled
