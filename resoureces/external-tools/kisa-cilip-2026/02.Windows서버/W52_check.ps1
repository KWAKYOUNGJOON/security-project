# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-52
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : Autologon기능제어
# @Description : 자동 로그온 기능 비활성화로 시스템 계정 정보 노출 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-52"
$ITEM_NAME = "Autologon기능제어"
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

# 1. Check AutoAdminLogon registry value
try {
    $autoAdminLogon = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue

    if (-not $autoAdminLogon -or $autoAdminLogon.AutoAdminLogon -eq '0' -or $autoAdminLogon.AutoAdminLogon -eq '') {
        $finalResult = "GOOD"
        $summary = "AutoAdminLogon 값이 없거나 0으로 설정됨 (자동 로그온 비활성화)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "AutoAdminLogon 값이 1로 설정됨 (자동 로그온 활성화 위험)"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon'"
    $autoAdminLogonValue = if ($autoAdminLogon) { $autoAdminLogon.AutoAdminLogon } else { "없음" }
    $commandOutput = "AutoAdminLogon=$autoAdminLogonValue"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'Autologon기능을사용하지않도록설정하여시스템계정정보노출을차단하기위함'
$threat = 'Autologon기능을사용하면침입자가해킹도구를이용하여레지스트리에저장된로그인계정및비밀번호정보유출위험존재'
$criteria_good = 'AutoAdminLogon값이없거나0으로설정된경우'
$criteria_bad = 'AutoAdminLogon값이1로설정된경우'
$remediation = '해당레지스트리값이존재하는경우0으로설정(HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon=0)'

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
