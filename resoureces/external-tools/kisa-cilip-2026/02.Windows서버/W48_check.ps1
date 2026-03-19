# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-48
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 로그온하지않고시스템종료허용
# @Description : 로그온하지 않고 시스템 종료 방지로 불법적인 시스템 종료 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-48"
$ITEM_NAME = "로그온하지않고시스템종료허용"
$SEVERITY = "상"
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

# 1. Check shutdown without logon setting
try {
    $winlogon = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
    $shutdownWithoutLogon = if ($winlogon) { $winlogon.ShutdownWithoutLogon } else { 1 }

    $output = "ShutdownWithoutLogon: $shutdownWithoutLogon"

    # 0 = Disabled (GOOD), 1 = Enabled (VULNERABLE)
    if ($shutdownWithoutLogon -eq 0) {
        $finalResult = "GOOD"
        $summary = "'로그온하지않고시스템종료허용'이'사용안함'으로 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'로그온하지않고시스템종료허용'이'사용'으로 설정됨"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ShutdownWithoutLogon'"
    $commandOutput = $output

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ShutdownWithoutLogon'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '시스템로그온화면의종료버튼을비활성화함으로써허가되지않은사용자를통한불법적인시스템종료를방지하고자함'
$threat = '로그온화면에"시스템종료"버튼이활성화되어있으면로그인을하지않고도불법적인시스템종료가가능하여정상적인서비스운영에영향을줌'
$criteria_good = '"로그온하지않고시스템종료허용"이"사용안함"으로설정된경우'
$criteria_bad = '"로그온하지않고시스템종료허용"이"사용"으로설정된경우'
$remediation = '"시스템종료:로그온하지않고시스템종료"정책을"사용안함"설정(로컬보안정책 > 로컬정책 > 보안옵션)'

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
