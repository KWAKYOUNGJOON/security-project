

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-18
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 원격지원금지정책설정
# @Description : 원격 지원 기능에 대한 금지 정책 설정 확인을 통해 외부 접근 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-18"
$ITEM_NAME = "원격지원금지정책설정"
$SEVERITY = "중"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check remote assistance policy (fAllowToGetHelp)
try {
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $defaultPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Services"
    $regName = "fAllowToGetHelp"

    $value = Get-ItemProperty -Path $policyPath -Name $regName -ErrorAction SilentlyContinue

    if ($value -ne $null) {
        $intValue = [int]$value.fAllowToGetHelp
        $commandOutput = "$regName : $intValue (Policy)"

        if ($intValue -eq 0) {
            $finalResult = "GOOD"
            $summary = "원격 지원 요청 금지됨 (정책 설정: fAllowToGetHelp = 0)"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "원격 지원 요청 허용됨 (정책 설정: fAllowToGetHelp = 1)"
            $status = "취약"
        }
    } else {
        # Check default path if policy not set
        $defaultValue = Get-ItemProperty -Path $defaultPath -Name $regName -ErrorAction SilentlyContinue

        if ($defaultValue -ne $null) {
            $intValue = [int]$defaultValue.fAllowToGetHelp
            $commandOutput = "$regName : $intValue (Default)"

            if ($intValue -eq 0) {
                $finalResult = "GOOD"
                $summary = "원격 지원 요청 금지됨 (기본값: fAllowToGetHelp = 0)"
                $status = "양호"
            } else {
                $finalResult = "VULNERABLE"
                $summary = "원격 지원 요청 허용됨 (기본값: fAllowToGetHelp = 1)"
                $status = "취약"
            }
        } else {
            $finalResult = "GOOD"
            $summary = "원격 지원 요청 금지됨 (값 없음: 기본적으로 비활성화)"
            $status = "양호"
            $commandOutput = "$regName : Not set (default: disabled)"
        }
    }

    $commandExecuted = "reg query HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services /v fAllowToGetHelp"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
    $commandExecuted = "reg query HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
}

# 2. Define guideline variables
$purpose = '원격 지원 금지로 무단 원격 접속 차단 및 시스템 보안 강화'
$threat = '원격 지원 허용 시 권한 없는 제3자 시스템 접근 가능하며, 피싱 공격을 악용한 무단 접속 및 정보 유출 위험 존재'
$criteria_good = 'fAllowToGetHelp = 0 (원격 지원 금지)'
$criteria_bad = 'fAllowToGetHelp = 1 (원격 지원 허용)'
$remediation = '그룹 정책: 컴퓨터 구성 > 관리 템플릿 > 시스템 > 원격 지원 > 원격 지원 요청 금지(사용), 또는 레지스트리: fAllowToGetHelp = 0 설정'

# 3. Save results using Save-DualResult
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

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
