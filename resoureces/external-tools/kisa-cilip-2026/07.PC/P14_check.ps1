

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-14
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 바이러스백신프로그램실시간감시기능활성화
# @Description : 바이러스 백신 프로그램의 실시간 감시 기능 활성화 상태 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-14"
$ITEM_NAME = "바이러스백신프로그램실시간감시기능활성화"
$SEVERITY = "상"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue

    $realTimeEnabled = $false
    if ($defender -ne $null -and $defender.RealTimeProtectionEnabled -eq $true) {
        $realTimeEnabled = $true
    }

    if ($realTimeEnabled) {
        $finalResult = "GOOD"
        $summary = "백신 실시간 감시 기능 활성화됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "백신 실시간 감시 기능 비활성화됨"
        $status = "취약"
    }

    $commandOutput = $defender | ConvertTo-Json -Compress -ErrorAction SilentlyContinue
    if ($null -eq $commandOutput) {
        $commandOutput = "진단 실패 또는 백신 미설치"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $($_.Exception.Message)"
}

# 2. Define guideline variables
$purpose = '백신 실시간 감시 기능 활성화로 악성코드 실시간 탐지 및 차단'
$threat = '실시간 감시 비활성화 시 악성코드 실행 즉시 탐지 불가능하며, 시스템 감염 및 전파 위험 심각'
$criteria_good = '백신 실시간 감시 기능 활성화됨'
$criteria_bad = '실시간 감시 기능 비활성화됨'
$remediation = '백신 프로그램 실시간 감시 기능 활성화. Windows Defender 경우: Windows 보안 > 바이러스 및 위협 방지 > 관리 설정 > 실시간 보호 켬. 타사 백신 경우: 해당 백신 프로그램 설정에서 실시간 감시 활성화'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted 'Get-MpComputerStatus' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
