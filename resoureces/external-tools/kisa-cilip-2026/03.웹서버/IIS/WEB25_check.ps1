# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-25
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : X-XSS-Protection 헤더 설정
# @Description : X-XSS-Protection HTTP 헤더를 설정하여 XSS(Cross-Site Scripting) 공격을 방지합니다. X-XSS-Protection 헤더 미설정 시 브라우저의 XSS 필터가 비활성화되어 XSS 공격에 취약합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-25"
$ITEM_NAME = "X-XSS-Protection 헤더 설정"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS X-XSS-Protection 헤더 확인
    $sites = Get-Website
    $sitesWithoutHeader = @()
    $sitesWithHeader = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        # web.config에서 customHeaders 확인
        $webConfig = Join-Path $path "web.config"
        $headerFound = $false

        if (Test-Path $webConfig) {
            [xml]$config = Get-Content $webConfig
            $httpProtocol = $config.configuration.'system.webServer'.httpProtocol
            if ($httpProtocol) {
                foreach ($header in $httpProtocol.customHeaders.Collection) {
                    if ($header.name -eq "X-XSS-Protection") {
                        $headerFound = $true
                        $sitesWithHeader += "Site: $siteName, X-XSS-Protection: $($header.value)"
                        break
                    }
                }
            }
        }

        # IIS 전체 설정 확인
        if (-not $headerFound) {
            $iisConfig = Get-WebConfiguration -Filter "/system.webServer/httpProtocol/customHeaders/add[@name='X-XSS-Protection']" -Location $siteName -ErrorAction SilentlyContinue
            if ($iisConfig) {
                $headerFound = $true
                $sitesWithHeader += "Site: $siteName, X-XSS-Protection: $($iisConfig.value)"
            }
        }

        if (-not $headerFound) {
            $sitesWithoutHeader += "Site: $siteName, X-XSS-Protection: Not configured"
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'"

    if ($sitesWithoutHeader.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "X-XSS-Protection 헤더가 설정되지 않은 사이트가 있습니다: " + ($sitesWithoutHeader[0] + " 외 " + ($sitesWithoutHeader.Count - 1) + "개")
        $status = "취약"
        $commandOutput = (($sitesWithHeader + $sitesWithoutHeader) -join "`n")
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에 X-XSS-Protection 헤더가 설정되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = $sitesWithHeader -join "`n"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'X-XSS-Protection 헤더 설정으로 XSS(Cross-Site Scripting) 공격 방지'
$threat = 'X-XSS-Protection 헤더 미설정 시 브라우저의 XSS 필터 비활성화로 XSS 공격에 취약'
$criteria_good = 'X-XSS-Protection 헤더가 설정된 경우 (1; mode=block 권장)'
$criteria_bad = 'X-XSS-Protection 헤더가 설정되지 않은 경우'
$remediation = 'IIS 관리자 > HTTP Response Headers > Add > Name: X-XSS-Protection, Value: 1; mode=block (web.config에 <add name="X-XSS-Protection" value="1; mode=block" />)'

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
