# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-19
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : 웹서비스SSI사용제한
# @Description : SSI(Server-Side Includes) 사용을 제한하여 악의적인 명령 실행 공격을 방지합니다. SSI 활성화 시 공격자가 악의적인 스크립트를 삽입하여 시스템 명령을 실행할 수 있는 보안 위협이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-19"
$ITEM_NAME = "웹서비스SSI사용제한"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS SSI (Server-Side Includes) 확인
    $sites = Get-Website
    $ssiEnabled = $false
    $siteInfo = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        # web.config에서 SSI 확인
        $webConfig = Join-Path $path "web.config"
        if (Test-Path $webConfig) {
            [xml]$config = Get-Content $webConfig
            $ssi = $config.configuration.'system.webServer'.serverSideInclude
            if ($ssi -and $ssi.enabled -eq "true") {
                $ssiEnabled = $true
                $siteInfo += "Site: $siteName, SSI: Enabled in web.config"
            }
        }

        # IIS 설정에서 SSI 확인
        $iisConfig = Get-WebConfiguration -Filter "/system.webServer/serverSideInclude" -Location $siteName -ErrorAction SilentlyContinue
        if ($iisConfig -and $iisConfig.Attributes.value.enabled -eq "true") {
            $ssiEnabled = $true
            $siteInfo += "Site: $siteName, SSI: Enabled in IIS config"
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/serverSideInclude'"

    if ($ssiEnabled) {
        $finalResult = "MANUAL"
        $summary = "SSI가 활성화되어 있습니다: " + ($siteInfo -join ", ") + " - 필요 여부 수동 확인 필요."
        $status = "수동진단"
        $commandOutput = $siteInfo -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "SSI가 비활성화되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "SSI: Disabled on all sites"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/serverSideInclude'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'SSI(Server Side Includes) 사용 제한으로 악의적인 명령 실행 방지'
$threat = 'SSI 활성화 시 공격자가 악의적인 스크립트를 삽입하여 시스템 명령 실행 가능'
$criteria_good = 'SSI가 비활성화되어 있거나 필수 기능 외에는 사용 제한된 경우'
$criteria_bad = 'SSI가 불필요하게 활성화되어 있는 경우'
$remediation = 'IIS 관리자 > 해당 사이트 > Server-Side Includes > Uninstall 또는 Disable 선택 (필요 시 확장자 제한 적용)'

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
