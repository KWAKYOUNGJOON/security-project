

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-19
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 불필요한IIS서비스구동점검
# @Description : 불필요한 IIS 서비스 구동 여부 점검으로 웹 서비스 취약점 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-19"
$ITEM_NAME = "불필요한IIS서비스구동점검"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check IIS service status
try {
    $iisInstalled = $false
    $w3svc = $null

    $w3svc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if ($w3svc) {
        $iisInstalled = $true
    }

    if (-not $iisInstalled) {
        $finalResult = "GOOD"
        $summary = "IIS 서비스가 설치되지 않음"
        $status = "양호"
        $commandOutput = "IIS (W3SVC) not installed"
    } elseif ($w3svc.Status -eq 'Stopped' -or $w3svc.StartType -eq 'Disabled') {
        $finalResult = "GOOD"
        $summary = "IIS 서비스가 비활성화되어 있거나 중지됨"
        $status = "양호"
        $commandOutput = "IIS (W3SVC) Status: $($w3svc.Status), StartType: $($w3svc.StartType)"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "IIS 서비스가 불필요하게 구동 중임"
        $status = "취약"
        $commandOutput = "IIS (W3SVC) Status: $($w3svc.Status), StartType: $($w3svc.StartType)"
    }

    $commandExecuted = "Get-Service -Name 'W3SVC'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name 'W3SVC'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '불필요한 IIS 서비스 구동 여부 점검으로 웹 서비스 취약점 방지'
$threat = '불필요한 IIS 서비스 구동 시 웹 서비스 관련 취약점 노출 및 리소스 낭비 위험 존재'
$criteria_good = 'IIS 서비스가 설치되지 않았거나 비활성화된 경우'
$criteria_bad = 'IIS 서비스가 활성화된 경우'
$remediation = 'IIS 관리자 > IIS 서비스 중지 또는 제거'

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
