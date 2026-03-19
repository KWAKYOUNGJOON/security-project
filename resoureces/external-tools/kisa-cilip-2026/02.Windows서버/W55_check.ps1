# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-55
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 사용자가프린터드라이버를설치할수없게함
# @Description : 프린터 드라이버 설치 제한으로 의도하지 않은 시스템 손상 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-55"
$ITEM_NAME = "사용자가프린터드라이버를설치할수없게함"
$SEVERITY = "중"
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

# 1. Check printer driver installation restriction policy
try {
    $secedit = secedit /export /cfg "$env:TEMP\secedit.tmp" 2>&1
    $content = Get-Content "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue
    $disableAddPrinter = 0

    if ($content -match 'DisableAddPrinter\s*=\s*(\d+)') {
        $disableAddPrinter = [int]$matches[1]
    }

    Remove-Item "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue

    if ($disableAddPrinter -eq 1) {
        $finalResult = "GOOD"
        $summary = "'사용자가프린터드라이버를설치할수없게함' 정책이 '사용'으로 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'사용자가프린터드라이버를설치할수없게함' 정책이 '사용안함'으로 설정됨"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 DisableAddPrinter 값 확인"
    $policyStatus = switch ($disableAddPrinter) {
        1 { "사용 (Administrators만 설치 가능)" }
        0 { "사용안함 (모든 사용자 설치 가능)" }
        default { "알 수 없음 ($disableAddPrinter)" }
    }
    $commandOutput = "DisableAddPrinter=$disableAddPrinter ($policyStatus)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 DisableAddPrinter 값 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '일반사용자를통한프린터드라이버설치를차단하여의도하지않은시스템손상을방지하기위함'
$threat = '서버에프린터드라이버를설치하는경우악의적인사용자가고의로잘못된프린터드라이버를설치하여컴퓨터를손상할수있으며,프린터드라이버로위장한악성코드를설치할위험존재'
$criteria_good = '''사용자가프린터드라이버를설치할수없게함''정책이''사용''인경우'
$criteria_bad = '''사용자가프린터드라이버를설치할수없게함''정책이''사용안함''인경우'
$remediation = '''사용자가프린터드라이버를설치할수없게함''정책을''사용''으로설정(로컬보안정책>로컬정책>보안옵션)'

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
