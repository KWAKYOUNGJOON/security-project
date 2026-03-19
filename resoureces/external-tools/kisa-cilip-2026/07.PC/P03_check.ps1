

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-03
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 복구콘솔에서자동로그온을금지하도록설정
# @Description : 시스템 복구 시 자동 로그온을 금지하여 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-03"
$ITEM_NAME = "복구콘솔에서자동로그온을금지하도록설정"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableAutomaticRebootLogon'
$commandOutput = ""
try {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $regName = 'DisableAutomaticRebootLogon'

    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
    if ($value.DisableAutomaticRebootLogon -eq 1) {
        $finalResult = "GOOD"
        $summary = "복구 콘솔 자동 로그온 금지 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "복구 콘솔 자동 로그온 금지 설정 안 됨"
        $status = "취약"
    }
    $commandOutput = reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRebootLogon 2>&1 | Out-String
} catch {
    $finalResult = "VULNERABLE"
    $summary = "복구 콘솔 자동 로그온 금지 설정 안 됨"
    $status = "취약"
    $commandOutput = "레지스트리 값 없음 또는 진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '시스템 복구 시 자동 로그온을 금지하여 무단 접근 방지'
$threat = '복구 콘솔 자동 로그온이 허용될 경우, 물리적 접근이 가능한 공격자가 권한 상승 가능'
$criteria_good = 'DisableAutomaticRebootLogon = 1'
$criteria_bad = '0 또는 값 없음'
$remediation = '레지스트리 편집기 또는 reg add 명령으로 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRebootLogon = 1 (DWORD) 설정'

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
