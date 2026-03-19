# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-13
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 하
# @Title       : 웹서비스디렉터리리스팅제거
# @Description : 웹 서버의 디렉터리 리스팅(Directory Listing) 기능을 제거하여 웹 서버 디렉터리 정보 노출을 방지합니다. 이 항목은 WEB-04와 동일한 내용을 다루지만 제거를 강조합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-13"
$ITEM_NAME = "웹서비스디렉터리리스팅제거"
$SEVERITY = "하"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 디렉터리 리스팅 제거 확인 (WEB-04와 동일하지만 다름을 강조)
    $sites = Get-Website
    $dirListingEnabled = $false
    $siteInfo = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        $webConfig = Join-Path $path "web.config"
        if (Test-Path $webConfig) {
            [xml]$config = Get-Content $webConfig
            $dirBrowse = $config.configuration.'system.webServer'.directoryBrowse
            if ($dirBrowse -and $dirBrowse.enabled -eq "true") {
                $dirListingEnabled = $true
                $siteInfo += "Site: $siteName, DirectoryBrowse: Enabled"
            }
        }

        $iisConfig = Get-WebConfiguration -Filter "/system.webServer/directoryBrowse" -Location $siteName
        if ($iisConfig -and $iisConfig.Attributes.value.enabled -eq "true") {
            $dirListingEnabled = $true
            $siteInfo += "Site: $siteName, IIS Config: Enabled"
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter `"/system.webServer/directoryBrowse`""

    if ($dirListingEnabled) {
        $finalResult = "VULNERABLE"
        $summary = "디렉터리 리스팅이 활성화되어 있습니다. 제거 필요: " + ($siteInfo -join ", ")
        $status = "취약"
        $commandOutput = $siteInfo -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에서 디렉터리 리스팅이 비활성화되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "DirectoryBrowse: Disabled on all sites"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter `"/system.webServer/directoryBrowse`""
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '디렉터리 리스팅 제거로 웹 서버 디렉터리 정보 노출 방지 (WEB-04 참고)'
$threat = '디렉터리 리스팅 활성화 시 공격자가 디렉터리 구조 확인 및 파일 정보 노출 위험'
$criteria_good = '디렉터리 리스팅이 비활성화된 경우'
$criteria_bad = '디렉터리 리스팅이 활성화된 경우'
$remediation = 'IIS 관리자 > 해당 사이트 > Directory Browsing > Disable 선택 (WEB-04와 동일)'

# 결과 저장
Save-DualResult -ItemId "${ITEM_ID}" `
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

exit 0
