# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-50
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 보안감사를로그할수없는경우즉시시스템종료
# @Description : 보안 감사 실패 시 시스템 종료 비활성화로 서비스 거부 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-50"
$ITEM_NAME = "보안감사를로그할수없는경우즉시시스템종료"
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

# 1. Check CrashOnAuditFail setting
try {
    $tempFile = Join-Path $env:TEMP "secedit_w50.tmp"

    # Export security policy to temp file
    $null = secedit /export /cfg $tempFile 2>&1

    $content = Get-Content $tempFile -ErrorAction Stop
    $crashOnAuditFail = 0

    # Parse CrashOnAuditFail
    if ($content -match 'CrashOnAuditFail\s*=\s*(\d+)') {
        $crashOnAuditFail = [int]$matches[1]
    }

    $output = "CrashOnAuditFail: $crashOnAuditFail"

    # Clean up temp file
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    # 0 = Disabled (GOOD), 1 = Enabled (VULNERABLE), 2 = Enabled (VULNERABLE)
    if ($crashOnAuditFail -eq 0) {
        $finalResult = "GOOD"
        $summary = "'보안감사를로그할수없는경우즉시시스템종료' 정책이 '사용안함'으로 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'보안감사를로그할수없는경우즉시시스템종료' 정책이 '사용'으로 설정됨"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 CrashOnAuditFail 값 확인"
    $commandOutput = $output

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 CrashOnAuditFail 값 확인"
    $commandOutput = "진단 실패: $_"

    # Clean up temp file if it exists
    $tempFile = Join-Path $env:TEMP "secedit_w50.tmp"
    Remove-Item $tempFile -ErrorAction SilentlyContinue
}

# 2. lib를 통한 결과 저장
$purpose = '해당정책을비활성화함으로써로그용량초과등의이유로이벤트를기록할수없는경우,해당정책으로인해시스템이비정상적으로종료되는것을방지하기위함'
$threat = '해당정책이활성화되어있는경우악의적인목적으로시스템종료를유발하여서비스거부공격에악용될수있으며,비정상적인시스템종료로인해시스템및데이터에손상을입힐위험존재'
$criteria_good = '"보안감사를로그할수없는경우즉시시스템종료"정책이"사용안함"으로되어있는경우'
$criteria_bad = '"보안감사를로그할수없는경우즉시시스템종료"정책이"사용"으로되어있는경우'
$remediation = '"보안감사를로그할수없는경우즉시시스템종료"정책을"사용안함"으로설정(로컬보안정책 > 로컬정책 > 보안옵션)'

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
