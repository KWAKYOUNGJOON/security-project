

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-13
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 콘솔로그온시로컬계정에서빈암호사용제한
# @Description : 빈 암호 사용 제한 정책 설정 여부 점검으로 빈 암호를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-13"
$ITEM_NAME = "콘솔로그온시로컬계정에서빈암호사용제한"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check LimitBlankPasswordUse policy
try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).LimitBlankPasswordUse

    if ($value -eq 1) {
        $finalResult = "GOOD"
        $summary = "'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 정책이 '사용'으로 설정됨"
        $status = "양호"
        $commandOutput = "LimitBlankPasswordUse = 1 (Enabled)"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 정책이 '사용 안 함'으로 설정됨 (보안 심각 위협)"
        $status = "취약"
        $commandOutput = "LimitBlankPasswordUse = $value (Disabled)"
    }

    $commandExecuted = "Get-ItemProperty -Path '$path'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty -Path '$path'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '빈 암호 사용 제한 정책 설정 여부 점검으로 빈 암호를 통한 무단 접근 방지'
$threat = '빈 암호 사용이 가능한 경우 공격자가 빈 암호를 가진 계정으로 쉽게 로그인 가능하여 시스템 장악 및 정보 유출 위험 존재'
$criteria_good = '''콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한''이 ''사용''으로 설정된 경우'
$criteria_bad = '''사용 안 함''으로 설정된 경우'
$remediation = '로컬 보안 정책 > 로컬 정책 > 보안 옵션 > ''계정: 로컬 계정에서 빈 암호 사용 제한''을 ''사용''으로 설정'

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
