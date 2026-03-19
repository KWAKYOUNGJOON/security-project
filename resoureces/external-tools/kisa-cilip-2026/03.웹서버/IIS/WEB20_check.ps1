# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-20
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 상
# @Title       : SSL/TLS활성화
# @Description : 웹 서비스에 SSL/TLS(HTTPS)를 활성화하여 통신 데이터를 암호화하고 중간자 공격(Man-in-the-Middle)을 방지합니다. SSL/TLS 미사용 시 평문 통화으로 인한 정보 탈취 및 도청 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-20"
$ITEM_NAME = "SSL/TLS활성화"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS SSL/TLS 바인딩 확인
    $sites = Get-Website
    $sitesWithoutSSL = @()
    $sitesWithSSL = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $bindings = Get-WebBinding -Name $siteName

        $hasHTTPS = $false
        foreach ($binding in $bindings) {
            if ($binding.Protocol -eq "https") {
                $hasHTTPS = $true
                $sitesWithSSL += "Site: $siteName, Port: $($binding.port), Certificate: Present"
                break
            }
        }

        if (-not $hasHTTPS) {
            $sitesWithoutSSL += "Site: $siteName, SSL: Not configured"
        }
    }

    $commandExecuted = "Get-Website; Get-WebBinding -Name [SiteName]"

    if ($sitesWithoutSSL.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "SSL/TLS가 구성되지 않은 웹사이트가 있습니다: " + ($sitesWithoutSSL -join ", ")
        $status = "취약"
        $commandOutput = ($sitesWithSSL + $sitesWithoutSSL) -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에 SSL/TLS가 구성되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = $sitesWithSSL -join "`n"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebBinding -Name [SiteName]"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'SSL/TLS 활성화로 통신 데이터 암호화 및 중간자 공격(Man-in-the-Middle) 방지'
$threat = 'SSL/TLS 미사용 시 평문 통신으로 인한 정보 탈취 및 도청 위험'
$criteria_good = '웹서비스가 HTTPS(SSL/TLS)를 사용하는 경우'
$criteria_bad = '웹서비스가 HTTP만 사용하거나 SSL/TLS가 비활성화된 경우'
$remediation = 'IIS 관리자 > 해당 사이트 > Bindings > Add > Type: https > SSL 인증서 선택 및 적용 (포트 443 권장)'

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
