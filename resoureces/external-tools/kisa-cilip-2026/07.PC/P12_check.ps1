

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-12
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : Windows자동로그인점검
# @Description : Windows 자동 로그인 기능이 비활성화되어 있는지 점검하여 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-12"
$ITEM_NAME = "Windows자동로그인점검"
$SEVERITY = "중"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$command = 'reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v AutoAdminLogon'
$commandResult = cmd /c "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v AutoAdminLogon 2>&1" | Out-String

try {
    $value = Get-ItemProperty -Path $regPath -Name AutoAdminLogon -ErrorAction Stop

    if ($value.AutoAdminLogon -eq 0 -or $value.AutoAdminLogon -eq "") {
        $finalResult = "GOOD"
        $summary = "자동 로그인 설정 안 됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "자동 로그인 설정됨"
        $status = "취약"
    }
} catch {
    # If registry key doesn't exist, it's actually good (no autologon)
    $finalResult = "GOOD"
    $summary = "자동 로그인 설정 안 됨"
    $status = "양호"
}

# 2. Define guideline variables
$purpose = '자동 로그인 금지로 물리적 접근 시 무단 로그인 방지 및 보안 강화'
$threat = '자동 로그인이 설정되면 비밀번호 입력 없이 시스템 접근 가능하여 물리적 접근 시 보안 위협 심각'
$criteria_good = 'AutoAdminLogon = 0 또는 값 없음'
$criteria_bad = 'AutoAdminLogon = 1 (자동 로그인 설정됨)'
$remediation = '레지스트리 편집기에서 HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon 값을 0으로 설정 또는 삭제'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandResult.Trim() `
    -CommandExecuted $command `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
