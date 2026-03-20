# Synthetic fixture for tests only.
# @ID: WEB-26
# @Title: IIS Suspicious Script Exposure
# @Severity: 상
# @Reference: KISA-WS-IIS-WEB26
$ITEM_ID = "WEB-26"
$ITEM_NAME = "IIS Suspicious Script Exposure"
$SEVERITY = "상"
$REFERENCE = "KISA-WS-IIS-WEB26"
$purpose = "의심 스크립트 존재 여부 탐지"
Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -Include *.asp,*.aspx
