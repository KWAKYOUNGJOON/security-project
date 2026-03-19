

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-02
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 비밀번호관리정책설정
# @Description : 비밀번호의 최소 길이를 8자 이상으로 설정하고 암호 복잡성 정책을 적용하여 비밀번호 추측 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-02"
$ITEM_NAME = "비밀번호관리정책설정"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = "net accounts; reg query `"HKLM\SYSTEM\CurrentControlSet\Control\Lsa`" /v PasswordComplexity"
$commandOutput = ""
try {
    # Check minimum password length
    $out = net accounts 2>&1 | Out-String
    $commandOutput = $out
    $minLength = 0
    $found = $false
    $issues = @()

    if ($out -match 'Minimum password length') {
        if ($out -match 'Minimum password length\s*:\s*(\d+)') {
            $minLength = [int]$matches[1]
            $found = $true
        }
    } elseif ($out -match '최소 암호 길이') {
        if ($out -match '최소 암호 길이\s*:\s*(\d+)') {
            $minLength = [int]$matches[1]
            $found = $true
        }
    }

    if ($minLength -lt 8) {
        $issues += "최소 암호 길이가 8자 미만임 (현재: ${minLength}자)"
    }

    # Check password complexity policy
    $complexityCheck = $false
    try {
        $complexityOutput = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity 2>&1 | Out-String
        $commandOutput += "`n`n" + $complexityOutput

        if ($complexityOutput -match 'PasswordComplexity\s+REG_DWORD\s+0x1') {
            $complexityCheck = $true
        } elseif ($complexityOutput -match 'PasswordComplexity\s+REG_DWORD\s+0x0') {
            $issues += "암호 복잡성 정책 비활성화됨"
        } else {
            $issues += "암호 복잡성 정책 설정 확인 불가 (레지스트리 값 없음)"
        }
    } catch {
        $issues += "암호 복잡성 정책 확인 실패: $_"
    }

    # Final judgment
    if ($issues.Count -eq 0 -and $minLength -ge 8 -and $complexityCheck) {
        $finalResult = "GOOD"
        $summary = "최소 암호 길이 8자 이상 및 암호 복잡성 정책 활성화됨"
        $status = "양호"
    } elseif ($issues.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "암호 정책 미준수: " + ($issues -join ", ")
        $status = "취약"
    } else {
        $finalResult = "MANUAL"
        $summary = "일부 정책 확인 불가: 수동 확인 필요"
        $status = "수동진단"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '비밀번호의 최소 길이를 8자 이상으로 설정하고 암호 복잡성 정책을 적용하여 비밀번호 추측 공격 방지'
$threat = '최소 암호 길이가 짧거나 복잡성 정책이 적용되지 않을 경우 무차별 대입 공격(Brute Force)이나 사전 공격(Dictionary Attack)으로 쉽게 노출될 위험'
$criteria_good = '8자 이상 및 암호 복잡성 정책 활성화'
$criteria_bad = '8자 미만 또는 암호 복잡성 정책 비활성화'
$remediation = '1. net accounts /minpwlen:8 명령 실행`n2. gpedit.msc > 컴퓨터 구성 > Windows 설정 > 보안 설정 > 계정 정책 > 암호 정책 > "암호에는 복잡성 요구" 활성화'

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
