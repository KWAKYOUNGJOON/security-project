

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-13
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 바이러스백신프로그램설치및주기적업데이트
# @Description : 바이러스 백신 프로그램 설치 및 주기적 업데이트 상태 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-13"
$ITEM_NAME = "바이러스백신프로그램설치및주기적업데이트"
$SEVERITY = "상"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $thirdParty = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction SilentlyContinue

    $hasDefender = $false
    $defenderEnabled = $false
    $defenderUpToDate = $false

    if ($defender -ne $null) {
        $hasDefender = $true
        if ($defender.RealTimeProtectionEnabled -eq $true) {
            $defenderEnabled = $true
        }
        if ($defender.AntivirusSignatureLastUpdated -ne $null) {
            $now = Get-Date
            $daysSinceUpdate = ($now - $defender.AntivirusSignatureLastUpdated).Days
            # 가이드라인 기준: KISA PC-13은 "최신 업데이트가 적용된 경우"를 양호로 판정
            # 7일 기준은 일반적인 백신 업데이트 주기(주간 업데이트)를 고려한 보안 권고사항
            # Microsoft, Symantec 등 주요 백신 벤더들은 주간 또는 일일 업데이트 권장
            if ($daysSinceUpdate -le 7) {
                $defenderUpToDate = $true
            }
        }
    }

    $hasThirdParty = $false
    $thirdPartyRunning = $false
    if ($thirdParty -ne $null) {
        $hasThirdParty = $true
        # Check if third-party antivirus is actually running (real-time protection enabled)
        foreach ($av in $thirdParty) {
            # productState bit 0 = 1 means real-time protection is enabled
            if ($av.productState -ne $null -and ($av.productState -band 1) -eq 1) {
                $thirdPartyRunning = $true
                break
            }
        }
    }

    if ($hasDefender -and $defenderEnabled -and $defenderUpToDate) {
        $finalResult = "GOOD"
        $summary = "백신 프로그램 설치되어 있고 실시간 감시 및 업데이트 정상"
        $status = "양호"
    } elseif ($hasThirdParty -and $thirdPartyRunning) {
        $finalResult = "GOOD"
        $summary = "백신 프로그램 설치되어 있고 실시간 감시 및 업데이트 정상"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "백신 프로그램 미설치 또는 실시간 감시/업데이트 미설정"
        $status = "취약"
    }

    $commandOutput = $defender | ConvertTo-Json -Compress -ErrorAction SilentlyContinue
    if ($null -eq $commandOutput) {
        $commandOutput = "진단 실패 또는 백신 미설치"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $($_.Exception.Message)"
}

# 2. Define guideline variables
$purpose = '백신 프로그램 설치 및 주기적 업데이트로 악성코드 감염 방지 및 시스템 보안 강화'
$threat = '백신 미설치 또는 업데이트 미시행 시 최신 악성코드 탐지 불가능하며, 시스템 감염 시 데이터 유출 및 파손 위험 심각'
$criteria_good = '백신 설치되고 실시간 감시 활성화 및 업데이트 정상 (7일 이내)'
$criteria_bad = '백신 미설치 또는 실시간 감시/업데이트 미설정'
$remediation = '백신 프로그램 설치 및 실시간 감시 기능 활성화. 자동 업데이트 설정 확인 (1주일 이내). Windows Defender 경우: Windows 보안 > 바이러스 및 위협 방지 > 보호 업데이트 확인'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted 'Get-MpComputerStatus' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
