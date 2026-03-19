

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-01
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 비밀번호의 주기적 변경
# @Description : 비밀번호를 주기적으로 변경하도록 강제하여 타인이 비밀번호를 도용하여 사용하는 위험을 최소화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-01"
$ITEM_NAME = "비밀번호의주기적변경"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'net accounts'
$commandOutput = ""
try {
    $out = net accounts 2>&1 | Out-String
    $commandOutput = $out
    $maxAge = 0

    if ($out -match 'Maximum password age') {
        if ($out -match 'Maximum password age\s*\(\s*days\s*\)\s*:\s*(\d+)') {
            $maxAge = [int]$matches[1]
        }
    } elseif ($out -match '최대 암호 사용 기간') {
        if ($out -match '최대 암호 사용 기간\s*\(\s*일\s*\)\s*:\s*(\d+)') {
            $maxAge = [int]$matches[1]
        }
    }
    if ($maxAge -gt 0 -and $maxAge -le 90) {
        $finalResult = "GOOD"
        $summary = "최대 암호 사용 기간이 90일 이하로 설정됨"
        $status = "양호"
    } elseif ($maxAge -gt 90) {
        $finalResult = "VULNERABLE"
        $summary = "최대 암호 사용 기간이 90일을 초과하거나 제한 없음으로 설정됨"
        $status = "취약"
    } else {
        $finalResult = "MANUAL"
        $summary = "진단 실패 또는 정책을 찾을 수 없음: 수동 확인 필요"
        $status = "수동진단"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '비밀번호를 주기적으로 변경하도록 강제하여 타인이 비밀번호를 도용하여 사용하는 위험을 최소화'
$threat = '비밀번호 변경 주기가 길거나 설정되지 않을 경우, 비밀노출 시 공격자가 장기간 시스템에 접근 가능'
$criteria_good = '90일 이하'
$criteria_bad = '90일 초과 또는 제한 없음'
$remediation = 'net accounts /maxpwage:90 명령 실행으로 최대 암호 사용 기간을 90일 이하로 설정'

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
