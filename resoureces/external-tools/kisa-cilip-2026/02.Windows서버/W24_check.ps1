# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-24
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : FTP접근제어설정
# @Description : FTP 서비스의 IP 기반 접근 제어로 무단 접속 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-24"
$ITEM_NAME = "FTP접근제어설정"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check FTP IP restriction settings
try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $ftpSite = Get-Website -Name 'FTP*' -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ftpSite) {
        $ipSecurity = Get-WebConfiguration -Filter '/system.ftpServer/security/ipSecurity' -PSPath 'IIS:\' -ErrorAction SilentlyContinue

        if ($ipSecurity -and ($ipSecurity.AllowUnlisted -eq $false -or $ipSecurity.ChildElements.Count -gt 0)) {
            $finalResult = "GOOD"
            $summary = "FTP 서비스에 IP 제한 설정이 적용됨"
            $status = "양호"
            $ipRestrictionDetails = "AllowUnlisted: $($ipSecurity.AllowUnlisted)"
            if ($ipSecurity.ChildElements.Count -gt 0) {
                $ipRestrictionDetails += "; Rules configured: $($ipSecurity.ChildElements.Count)"
            }
            $commandOutput = $ipRestrictionDetails
        } else {
            $finalResult = "VULNERABLE"
            $summary = "FTP 서비스에 IP 주소 기반 접근 제한이 설정되지 않음"
            $status = "취약"
            $commandOutput = if ($ipSecurity) { "No IP restrictions configured; AllowUnlisted: $($ipSecurity.AllowUnlisted)" } else { "IP Security not configured" }
        }
    } else {
        $finalResult = "GOOD"
        $summary = "FTP 서비스가 설치되지 않음 또는 FTP 사이트가 구성되지 않음"
        $status = "양호"
        $commandOutput = "No FTP site configured"
    }

    $commandExecuted = "Get-WebConfiguration -Filter '/system.ftpServer/security/ipSecurity' -PSPath 'IIS:\'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter '/system.ftpServer/security/ipSecurity' -PSPath 'IIS:\'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'FTP 서비스의 IP 기반 접근 제어로 무단 접속 방지'
$threat = 'FTP IP 제한 미설정 시 인증되지 않은 모든 IP에서 접근 가능'
$criteria_good = 'FTP 서비스에 IP 제한이 설정된 경우'
$criteria_bad = 'FTP 서비스에 IP 제한이 없는 경우'
$remediation = 'IIS 관리자 > FTP 사이트 > IP 주소 및 도메인 제한 설정'

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
    -GuidelineRemediation $remediation

# run_all 모드가 아닐 때만 완료 메시지 출력
if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($finalResult)"
}

exit 0
