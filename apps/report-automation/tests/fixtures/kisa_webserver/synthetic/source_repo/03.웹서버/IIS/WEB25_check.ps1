# Synthetic fixture for tests only.
# @ID: WEB-25
# @Title: IIS Version Verification
# @Severity: 중
# @Reference: KISA-WS-IIS-WEB25
$ITEM_ID = "WEB-25"
$ITEM_NAME = "IIS Version Verification"
$SEVERITY = "중"
$REFERENCE = "KISA-WS-IIS-WEB25"
$purpose = "IIS 버전 및 패치 수준 확인"
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp'
