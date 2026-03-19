# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-16
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 하
# @Title       : 웹서버헤더정보노출제한
# @Description : HTTP 응답 헤더에서 Server, X-Powered-By 등 서버 정보를 제거하거나 제한하여 정보 유출을 방지합니다. 서버 버전 정보 노출 시 공격자가 해당 버전의 취약점을 악용한 공격이 가능해집니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-16"
$ITEM_NAME = "웹서버헤더정보노출제한"
$SEVERITY = "하"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS Server Header 및 Version 정보 확인
    $sites = Get-Website
    $serverHeaderExposed = $false
    $siteInfo = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        # web.config에서 customHeaders 확인
        $webConfig = Join-Path $path "web.config"
        if (Test-Path $webConfig) {
            [xml]$config = Get-Content $webConfig
            $httpProtocol = $config.configuration.'system.webServer'.httpProtocol
            if ($httpProtocol) {
                $serverHeaderRemoved = $false
                foreach ($header in $httpProtocol.customHeaders.Collection) {
                    if ($header.name -eq "Server" -and $header.value -eq "") {
                        $serverHeaderRemoved = $true
                        break
                    }
                }
                if (-not $serverHeaderRemoved) {
                    $serverHeaderExposed = $true
                    $siteInfo += "Site: $siteName, Server Header: Exposed"
                }
            } else {
                $serverHeaderExposed = $true
                $siteInfo += "Site: $siteName, Server Header: Exposed (default)"
            }
        } else {
            $serverHeaderExposed = $true
            $siteInfo += "Site: $siteName, Server Header: Exposed (no config)"
        }
    }

    # URL Rewrite 모듈 설치 확인
    $rewriteInstalled = Get-WebModule -Name "RewriteModule" -ErrorAction SilentlyContinue

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'"

    if ($serverHeaderExposed) {
        $finalResult = "VULNERABLE"
        $summary = "Server 헤더 정보가 노출되고 있습니다: " + ($siteInfo -join ", ")
        $status = "취약"
        $commandOutput = $siteInfo -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "Server 헤더 정보가 제한되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Server Header: Removed or restricted on all sites"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹서버 헤더 정보(Server, Version, X-Powered-By 등) 노출 제한으로 정보 유출 방지'
$threat = '서버 버전 정보 노출 시 공격자가 해당 버전의 취약점을 악용한 공격 가능'
$criteria_good = 'Server 헤더, X-Powered-By 헤더 등 서버 정보 노출이 제한된 경우'
$criteria_bad = 'Server 헤더, X-Powered-By 헤더 등을 통해 서버 정보가 노출되는 경우'
$remediation = 'IIS 관리자 > HTTP Response Headers > Remove 또는 URL Rewrite 모듈 사용 (web.config에 <remove name="X-Powered-By"> 및 customHeader로 Server 헤더 제거)'

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
