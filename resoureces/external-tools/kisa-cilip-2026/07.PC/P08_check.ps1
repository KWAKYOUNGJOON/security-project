

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-08
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 멀티부팅 금지
# @Description : 대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-08"
$ITEM_NAME = "대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정"
$SEVERITY = "중"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic using bcdedit
# bcdedit의 부트 로더 식별자(identifier) 개수로 멀티부팅 여부 판단
# Windows Boot Manager + 1개의 Windows Boot Loader = 단일 부팅 (양호)
# Windows Boot Manager + 2개 이상의 Boot Loader = 멀티 부팅 (취약)
$commandExecuted = 'bcdedit /enum'
$commandOutput = ""
try {
    $bcdOutput = bcdedit /enum 2>&1 | Out-String
    $commandOutput = $bcdOutput
    $identifiers = $bcdOutput | Select-String -Pattern 'identifier\s+' | Where-Object { $_ -match '\{[A-F0-9-]+\}' }
    $actualBootEntries = ($identifiers | Where-Object { $_ -match 'bootload' }).Count

    if ($actualBootEntries -le 1) {
        $finalResult = "GOOD"
        $summary = "단일 부팅 구성 (Windows OS만 설치됨)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "멀티 부팅 구성 감지 (2개 이상의 OS 부팅 가능)"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: msconfig 또는 레지스트리 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패"
}

# 2. lib를 통한 결과 저장
$purpose = '사용자 PC에서 하나의 OS만 설치되도록 하여 다른 OS를 이용한 주요 파일 시스템 접근 차단'
$threat = '멀티 부팅이 가능한 경우, 공격자는 해당 PC의 주요 OS 이외에 다른 OS로 부팅하여 중요한 정보가 들어있는 파일 시스템에 접근하여 주요 정보를 획득할 수 있는 위험 존재'
$criteria_good = 'PC 내에 하나의 OS만 설치된 경우'
$criteria_bad = 'PC 내에 2개 이상의 OS가 설치된 경우'
$remediation = '하나의 OS만 설치하여 운영. 사용하지 않는 OS는 msconfig 또는 레지스트리 편집기로 부팅 항목에서 삭제'

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
