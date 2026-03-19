

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-10
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 주기적보안패치및벤더권고사항적용
# @Description : 주기적인 보안 패치 및 벤더 권고 사항 적용하여 시스템 취약점 최소화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-10"
$ITEM_NAME = "주기적보안패치및벤더권고사항적용"
$SEVERITY = "상"
$CATEGORY = "3.패치관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
    $command = 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update /v AUOptions'
    $commandResult = reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions 2>&1 | Out-String

    $auOptions = Get-ItemProperty -Path $regPath -Name AUOptions -ErrorAction SilentlyContinue

    if ($auOptions -eq $null) {
        $finalResult = "MANUAL"
        $summary = "수동 확인 필요"
        $status = "수동진단"
    } elseif ($auOptions.AUOptions -eq 4 -or $auOptions.AUOptions -eq 5) {
        $finalResult = "GOOD"
        $summary = "Windows 자동 업데이트 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "Windows 자동 업데이트 설정 안 됨"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandResult = $_.Exception.Message
}

# 2. Define guideline variables
$purpose = '주기적 보안 패치 및 벤더 권고사항 적용으로 알려진 취약점 제거 및 시스템 보안 강화'
$threat = '보안 패치 미적용 시 알려진 취약점 공격 가능성 높으며, 제로디 공격 등 악용 위험 존재'
$criteria_good = 'Windows 자동 업데이트 설정됨'
$criteria_bad = '자동 업데이트 설정 안 됨'
$remediation = 'Windows 업데이트 설정: 설정 > 업데이트 및 보안 > Windows 업데이트 > 고급 옵션 > 자동 업데이트 구성에서 ''자동화된 업데이트 설치'' 또는 ''업데이트 확인 및 설치'' 선택'

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
