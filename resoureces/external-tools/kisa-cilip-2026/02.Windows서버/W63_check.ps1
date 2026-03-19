# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-63
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 도메인컨트롤러-사용자의시간동기화
# @Description : Kerberos 시간 동기화 설정으로 재전송 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-63"
$ITEM_NAME = "도메인컨트롤러-사용자의시간동기화"
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

# 1. Check Kerberos MaxClockSkew setting
try {
    $kerberosPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'MaxClockSkew' -ErrorAction SilentlyContinue

    if ($kerberosPolicy -and $kerberosPolicy.MaxClockSkew -le 5) {
        $finalResult = "GOOD"
        $summary = "컴퓨터 시계 동기화 최대 허용 오차가 5분 이하로 설정됨"
        $status = "양호"
    } elseif ($kerberosPolicy -and $kerberosPolicy.MaxClockSkew -gt 5) {
        $finalResult = "VULNERABLE"
        $summary = "컴퓨터 시계 동기화 최대 허용 오차가 5분 초과로 설정됨"
        $status = "취약"
    } else {
        $finalResult = "MANUAL"
        $summary = "도메인 컨트롤러가 아니거나 설정 확인 불가능 (수동 진단 필요)"
        $status = "수동진단"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'MaxClockSkew'"
    $commandOutput = if ($kerberosPolicy) { "MaxClockSkew: $($kerberosPolicy.MaxClockSkew) minutes" } else { "레지스트리 키 없음" }

} catch {
    $finalResult = "MANUAL"
    $summary = "도메인 컨트롤러가 아니거나 설정 확인 불가능 (수동 진단 필요)"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'MaxClockSkew'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '이설정은Kerberos가클라이언트시계의시간과서버시계의시간사이에서허용되는최대시간차이(분)를결정하는동시에두시계의동기를고려하여,재전송공격을방지하기위함'
$threat = 'ReplayAttack이란프로토콜상메시지를복사한후재전송함으로써승인된사용자로오인하게만들어내부침입및정보유출위험존재'
$criteria_good = '컴퓨터시계동기화최대허용오차값이5분이하인경우'
$criteria_bad = '컴퓨터시계동기화최대허용오차값이5분초과인경우'
$remediation = 'Kerberos사용시컴퓨터시계동기화최대허용오차값5분이하로설정(로컬보안정책>계정정책>Kerberos정책)'

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
