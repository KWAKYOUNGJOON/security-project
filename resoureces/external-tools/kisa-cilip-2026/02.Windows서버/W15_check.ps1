

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-15
# @Category    : Windows Server
# @Platform    : Windows Server 2016, 2019, 2022
# @Severity    : 상
# @Title       : 사용자개인키사용시암호입력
# @Description : 사용자 개인키(인증서) 사용 시 암호 입력 요구 정책 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-15"
$ITEM_NAME = "사용자개인키사용시암호입력"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. check ProtectionPolicy for private key password
try {
    $prop = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\Protected" -ErrorAction SilentlyContinue

    if ($prop -and $prop.ProtectionPolicy -eq 1) {
        $finalResult = "GOOD"
        $summary = "사용자 개인키 사용 시마다 암호 입력이 요구됨"
        $status = "양호"
        $commandOutput = "ProtectionPolicy = 1 (Password required)"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "사용자 개인키 사용 시 암호 입력이 요구되지 않음"
        $status = "취약"
        $commandOutput = "ProtectionPolicy = $(if ($prop) { $prop.ProtectionPolicy } else { 'Not set' }) (No password required)"
    }

    $commandExecuted = "reg query 'HKLM\SOFTWARE\Microsoft\Cryptography\Protect\Providers\Protected' /v ProtectionPolicy"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 레지스트리 확인 필요"
    $status = "수동진단"
    $commandExecuted = "reg query 'HKLM\SOFTWARE\Microsoft\Cryptography\Protect\Providers\Protected' /v ProtectionPolicy"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '사용자 개인키(인증서) 사용 시 암호 입력 요구 정책 설정 여부 점검'
$threat = '개인키 사용 시 암호 미입력 시 개인키 노출 위험 존재하며, 노출 시 암호화 통신 내용 복호화 및 위변조 가능'
$criteria_good = '개인키 사용 시 암호 입력이 요구되는 경우'
$criteria_bad = '암호 입력이 요구되지 않는 경우'
$remediation = '로컬 보안 정책 > 로컬 정책 > 보안 옵션 > '

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
