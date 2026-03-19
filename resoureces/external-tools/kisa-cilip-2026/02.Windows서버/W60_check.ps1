# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-60
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 보안채널데이터디지털암호화또는서명
# @Description : 보안 채널 데이터 암호화 및 서명으로 인증 트래픽 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-60"
$ITEM_NAME = "보안채널데이터디지털암호화또는서명"
$SEVERITY = "중"
$CATEGORY = "5.보안관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check secure channel data encryption or signing
try {
    $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $requireSignOrSeal = if ($lsa) { $lsa.RequireSignOrSeal } else { 0 }
    $requireSignOrSeal2 = if ($lsa) { $lsa.RequireSignOrSeal2 } else { 0 }
    $allSet = ($requireSignOrSeal -eq 1) -and ($requireSignOrSeal2 -ge 1)

    if ($allSet) {
        $finalResult = "GOOD"
        $summary = "보안 채널 데이터 디지털 암호화 및 서명이 활성화됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "보안 채널 데이터 디지털 암호화 또는 서명이 비활성화됨"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' (RequireSignOrSeal, RequireSignOrSeal2)"
    $commandOutput = "RequireSignOrSeal: $requireSignOrSeal, RequireSignOrSeal2: $requireSignOrSeal2"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' (RequireSignOrSeal, RequireSignOrSeal2)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '해당정책을활성화하여보안채널의서명또는암호화를협상하지않는한보안채널을확립하지않기위함'
$threat = '보안채널이암호화되지않으면인증트래픽끼어들기공격,반복공격및기타유형의네트워크공격등의위험존재'
$criteria_good = '도메인구성원:보안채널데이터를디지털암호화또는서명(항상),보안채널데이터디지털서명(가능한경우),보안채널데이터를디지털암호화(가능한경우)3가지정책모두''사용''으로되어있는경우'
$criteria_bad = '3가지정책중일부가''사용안함''으로되어있는경우'
$remediation = '보안채널데이터를디지털암호화또는서명관련3개정책을모두''사용''으로설정'

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
