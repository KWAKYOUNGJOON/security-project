

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-09
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 비밀번호관리정책설정
# @Description : 비밀번호 관리 정책 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-09"
$ITEM_NAME = "비밀번호관리정책설정"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check password policy settings
try {
    $output = net accounts 2>&1 | Out-String
    $complexity = $false
    $minLength = 0
    $maxAge = 0
    $minAge = 0

    # Check password complexity (Korean: 사용, English: Enabled)
    if ($output -match '암호 복잡성 요구.*:\s*(\w+)') {
        if ($matches[1] -eq '사용' -or $matches[1] -eq 'Enabled') {
            $complexity = $true
        }
    }

    # Check minimum password length
    if ($output -match '최소 암호 길이.*:\s*(\d+)') {
        $minLength = [int]$matches[1]
    }
    elseif ($output -match 'Minimum password length.*:\s*(\d+)') {
        $minLength = [int]$matches[1]
    }

    # Check maximum password age
    if ($output -match '최대 암호 사용 기간.*:\s*(\d+)') {
        $maxAge = [int]$matches[1]
    }
    elseif ($output -match 'Maximum password age.*:\s*(\d+)') {
        $maxAge = [int]$matches[1]
    }

    # Check minimum password age
    if ($output -match '최소 암호 사용 기간.*:\s*(\d+)') {
        $minAge = [int]$matches[1]
    }
    elseif ($output -match 'Minimum password age.*:\s*(\d+)') {
        $minAge = [int]$matches[1]
    }

    $details = "Complexity: $complexity, MinLength: $minLength, MaxAge: $maxAge, MinAge: $minAge"

    if ($complexity -and $minLength -ge 8 -and $maxAge -le 90 -and $maxAge -gt 0 -and $minAge -ge 1) {
        $finalResult = "GOOD"
        $summary = "비밀번호 관리 정책이 모두 적용됨 (복잡성 사용, 최소 길이 8자 이상, 최대/최소 사용 기간 설정)"
        $status = "양호"
        $commandOutput = $details
    } else {
        $finalResult = "VULNERABLE"
        $issues = @()
        if (-not $complexity) { $issues += "복잡성 미사용" }
        if ($minLength -lt 8) { $issues += "최소 길이 $minLength 자 (< 8)" }
        if ($maxAge -eq 0 -or $maxAge -gt 90) { $issues += "최대 기간 $maxAge 일 (> 90 또는 0)" }
        if ($minAge -lt 1) { $issues += "최소 기간 $minAge 일 (< 1)" }
        $summary = "비밀번호 관리 정책 미준수: " + ($issues -join ', ')
        $status = "취약"
        $commandOutput = $details
    }

    $commandExecuted = "net accounts"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "net accounts"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '계정 비밀번호 관리 정책 설정 여부 점검으로 비밀번호 보안 강화'
$threat = '비밀번호 관리 정책 미준수 시 무차별 대입 공격이나 비밀번호 추측 공격에 쉽게 크랙될 위험 존재'
$criteria_good = '계정 비밀번호 관리 정책이 모두 적용된 경우'
$criteria_bad = '계정 비밀번호 관리 정책이 모두 적용되어 있지 않은 경우'
$remediation = '로컬 보안 정책 > 계정 정책 > 암호 정책 > '

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
