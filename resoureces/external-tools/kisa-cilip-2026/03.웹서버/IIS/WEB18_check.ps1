# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-18
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : 웹서비스WebDAV비활성화
# @Description : WebDAV(Web Distributed Authoring and Versioning)를 비활성화하여 파일 무단 수정, 삭제, 업로드 등 악의적인 조작을 방지합니다. WebDAV 활성화 시 인증된 사용자가 HTTP를 통해 파일을 직접 조작할 수 있어 보안 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-18"
$ITEM_NAME = "웹서비스WebDAV비활성화"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS WebDAV 설치 및 활성화 확인
    $sites = Get-Website
    $webdavEnabled = $false
    $siteInfo = @()

    # WebDAV 모듈 설치 확인
    $webdavInstalled = Get-WebModule -Name "WebDAVModule" -ErrorAction SilentlyContinue

    if ($webdavInstalled) {
        foreach ($site in $sites) {
            $siteName = $site.Name

            # WebDAV 설정 확인
            $webdavSettings = Get-WebConfiguration -Filter "/system.webServer/webdav/authoring" -Location $siteName -ErrorAction SilentlyContinue
            if ($webdavSettings -and $webdavSettings.Enabled -eq "true") {
                $webdavEnabled = $true
                $siteInfo += "Site: $siteName, WebDAV: Enabled"
            }
        }
    }

    $commandExecuted = "Get-WebModule -Name 'WebDAVModule'; Get-WebConfiguration -Filter '/system.webServer/webdav/authoring'"

    if ($webdavEnabled) {
        $finalResult = "VULNERABLE"
        $summary = "WebDAV가 활성화되어 있습니다: " + ($siteInfo -join ", ")
        $status = "취약"
        $commandOutput = $siteInfo -join "`n"
    } elseif ($webdavInstalled) {
        $finalResult = "GOOD"
        $summary = "WebDAV가 설치되어 있지만 비활성화되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "WebDAV: Installed but Disabled"
    } else {
        $finalResult = "GOOD"
        $summary = "WebDAV가 설치되어 있지 않습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "WebDAV: Not Installed"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebModule -Name 'WebDAVModule'; Get-WebConfiguration -Filter '/system.webServer/webdav/authoring'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'WebDAV 비활성화로 파일 무단 수정, 삭제, 업로드 등 악의적인 조작 방지'
$threat = 'WebDAV 활성화 시 인증된 사용자가 HTTP를 통해 파일을 조작할 수 있어 보안 위험'
$criteria_good = 'WebDAV가 비활성화되어 있거나 설치되지 않은 경우'
$criteria_bad = 'WebDAV가 활성화되어 있는 경우'
$remediation = 'IIS 관리자 > 해당 사이트 > WebDAV > Disable 선택 또는 WebDAV 모듈 제거 (Remove-WindowsFeature Web-DAV-Locator)'

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
