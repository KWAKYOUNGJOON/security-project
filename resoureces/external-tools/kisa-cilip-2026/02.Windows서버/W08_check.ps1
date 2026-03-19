

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-08
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 계정잠금기간설정
# @Description : 계정 잠금 기간 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-08"
$ITEM_NAME = "계정잠금기간설정"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check account lockout duration and reset time
try {
    $output = net accounts 2>&1 | Out-String
    $duration = 0
    $reset = 0

    # Try Korean patterns first
    if ($output -match '잠금 기간.*:\s*(\d+)') {
        $duration = [int]$matches[1]
    }
    elseif ($output -match 'LockoutDuration.*:\s*(\d+)') {
        $duration = [int]$matches[1]
    }

    if ($output -match '잠금 카운터 재설정.*:\s*(\d+)') {
        $reset = [int]$matches[1]
    }
    elseif ($output -match 'ResetTime.*:\s*(\d+)') {
        $reset = [int]$matches[1]
    }

    if ($duration -ge 60 -and $reset -ge 60) {
        $finalResult = "GOOD"
        $summary = "계정 잠금 기간 및 잠금 카운터 재설정 시간이 60분 이상으로 적절히 설정됨"
        $status = "양호"
        $commandOutput = "Lockout Duration: $duration minutes, Reset Time: $reset minutes"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "계정 잠금 기간 및/또는 잠금 카운터 재설정 시간이 60분 미만이거나 설정되지 않음 (보안 취약)"
        $status = "취약"
        $commandOutput = "Lockout Duration: $duration minutes, Reset Time: $reset minutes (both should be >= 60)"
    }

    $commandExecuted = "net accounts"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "net accounts"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '사용자 계정 잠금 기간 정책 설정 여부 점검으로 공격자의 자유로운 비밀번호 유추 공격 차단'
$threat = '로그인 실패 시 일정 시간 동안 계정 잠금을 하지 않은 경우, 공격자의 자동화된 비밀번호 추측 공격이 가능하여 사용자 계정의 비밀번호 정보 유출 위험 존재'
$criteria_good = '''계정 잠금 기간'' 및 ''계정 잠금 수를 원래대로 설정 기간''이 60분 이상으로 설정된 경우'
$criteria_bad = '60분 미만으로 설정되거나 설정되지 않은 경우'
$remediation = '로컬 보안 정책 > 계정 정책 > 계정 잠금 정책 > ''계정 잠금 기간'', ''다음 시간 후 계정 잠금 수를 원래대로 설정''을 각각 ''60분'' 설정'

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
