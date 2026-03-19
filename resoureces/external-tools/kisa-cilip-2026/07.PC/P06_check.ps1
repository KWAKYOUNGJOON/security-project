

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-06
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 비인가상용메신저사용금지
# @Description : 비인가 상용 메신저 프로그램의 사용을 금지하여 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-06"
$ITEM_NAME = "비인가상용메신저사용금지"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = "reg query `"HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client`" /v Disabled"
$commandOutput = ""
try {
    # Check registry policy for Windows Messenger disable status
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
    $registryOutput = reg query "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v Disabled 2>&1 | Out-String
    $commandOutput = $registryOutput

    # Check if policy exists and is set to disable (Disabled = 1)
    $policyDisabled = $false
    if ($registryOutput -match 'Disabled\s+REG_DWORD\s+0x1') {
        $policyDisabled = $true
    }

    # Also check Windows Messenger service status
    $messengerService = Get-Service -Name "Messenger" -ErrorAction SilentlyContinue
    $serviceRunning = $false
    if ($messengerService -ne $null -and $messengerService.Status -eq "Running") {
        $serviceRunning = $true
    }

    if ($policyDisabled -and -not $serviceRunning) {
        $finalResult = "GOOD"
        $summary = "Windows Messenger 실행 중지됨 (정책 비활성화 및 서비스 중지)"
        $status = "양호"
    } elseif ($serviceRunning) {
        $finalResult = "VULNERABLE"
        $summary = "Windows Messenger 실행 중 (서비스 상태: $($messengerService.Status), 시작 유형: $($messengerService.StartType))"
        $status = "취약"
    } else {
        # Policy not set but service not running - check if policy exists
        if ($registryOutput -match 'ERROR') {
            $finalResult = "VULNERABLE"
            $summary = "Windows Messenger 비활성화 정책 미설정 (레지스트리 정책 없음)"
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "Windows Messenger 실행 중지됨"
            $status = "양호"
        }
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'Windows Messenger 실행 중지를 통하여 메신저를 이용한 개인정보 및 내부 주요 정보 유출 방지'
$threat = 'Windows Messenger가 실행 중인 경우, 메신저를 통해 주요 정보가 유출되거나 악성코드가 유입될 위험이 존재'
$criteria_good = 'Windows Messenger가 실행 중지된 상태'
$criteria_bad = 'Windows Messenger가 실행 중이거나 비활성화 정책 미설정'
$remediation = 'gpedit.msc > 컴퓨터 구성 > 관리 템플릿 > Windows 구성 요소 > Windows Messenger > "Windows Messenger를 실행 허용 안 함" 설정을 "사용"으로 설정'

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
