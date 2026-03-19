

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-15
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : OS에서제공하는침입차단기능활성화
# @Description : OS에서 제공하는 침입 차단 기능이 활성화되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-15"
$ITEM_NAME = "OS에서제공하는침입차단기능활성화"
$SEVERITY = "상"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop

    $allEnabled = $true
    foreach ($profile in $profiles) {
        if ($profile.Enabled -eq $false) {
            $allEnabled = $false
            break
        }
    }

    if ($allEnabled) {
        $finalResult = "GOOD"
        $summary = "Windows 방화벽 활성화됨 (모든 프로필)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "Windows 방화벽 비활성화됨 (하나 이상 프로필)"
        $status = "취약"
    }

    $commandOutput = $profiles | ConvertTo-Json -Compress -ErrorAction SilentlyContinue
    if ($null -eq $commandOutput) {
        $commandOutput = "진단 실패"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $($_.Exception.Message)"
}

# 2. Define guideline variables
$purpose = 'OS 침입차단기능(방화벽) 활성화로 무단 접속 차단 및 네트워크 보안 강화'
$threat = '방화벽 비활성화 시 외부 공격자의 무단 접속 가능하며, 포트 스캔, 서비스 공격, 데이터 유출 위험 심각'
$criteria_good = 'Windows 방화벽 활성화됨 (도메인, 사설, 공용 모두)'
$criteria_bad = '하나 이상 프로필에서 방화벽 비활성화됨'
$remediation = 'Windows 방화벽 활성화. 제어판 > Windows Defender 방화벽 > 사용자 지정 설정 켬. 또는 PowerShell: Set-NetFirewallProfile -Enabled True -Profile Domain,Private,Public'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted 'Get-NetFirewallProfile' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
