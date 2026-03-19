

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-01
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : Administrator 계정 이름 변경
# @Description : 기본 Administrator 계정 이름을 변경하여 무단 접근 위험 방지 및 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-01"
$ITEM_NAME = "Administrator계정이름변경"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check if Administrator account name is changed
try {
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like "*-500" }

    if ($admin.Name -eq "Administrator") {
        $finalResult = "VULNERABLE"
        $summary = "기본 Administrator 계정 이름 사용 중 (보안 위험)"
        $status = "취약"
    } else {
        $finalResult = "GOOD"
        $summary = "Administrator 계정 이름이 변경됨"
        $status = "양호"
    }

    $commandExecuted = "Get-LocalUser | Where-Object { `$_.SID.Value -like '*-500' }"
    $commandOutput = "Admin Name: $($admin.Name)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalUser | Where-Object { `$_.SID.Value -like '*-500' }"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'Administrator 계정 이름 변경으로 무단 접근 위험 방지 및 보안 강화'
$threat = '기본 Administrator 계정 이름 사용 시 공격자가 관리자 계정을 쉽게 식별 가능하며, 무단 접근 및 시스템 장악 위험 심각'
$criteria_good = 'Administrator 계정 이름이 다른 이름으로 변경됨'
$criteria_bad = 'Administrator 계정이 기본 이름 사용 중'
$remediation = '로컬 사용자 및 그룹 > Administrator 계정 이름 변경 > 보안 강화를 위해 고유한 이름으로 변경'

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
