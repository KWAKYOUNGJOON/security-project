# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-53
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 이동식미디어포맷및꺼내기허용
# @Description : 이동식 미디어 포맷 및 꺼내기 권한 제한으로 불법적인 매체 처리 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-53"
$ITEM_NAME = "이동식미디어포맷및꺼내기허용"
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

# 1. Check removable media formatting and eject policy (AllocateDASD)
try {
    $secedit = secedit /export /cfg "$env:TEMP\secedit.tmp" 2>&1
    $content = Get-Content "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue
    $administratorsOnly = 0

    if ($content -match 'AllocateDASD\s*=\s*(\d+)') {
        $administratorsOnly = [int]$matches[1]
    }

    Remove-Item "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue

    if ($administratorsOnly -eq 0) {
        $finalResult = "GOOD"
        $summary = "'이동식미디어포맷및꺼내기허용' 정책이 'Administrators'로 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'이동식미디어포맷및꺼내기허용' 정책이 'Administrators'로 설정되지 않음"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 AllocateDASD 값 확인"
    $policyValue = switch ($administratorsOnly) {
        0 { "Administrators" }
        1 { "Administrators 및 Power Users" }
        default { "알 수 없음 ($administratorsOnly)" }
    }
    $commandOutput = "AllocateDASD=$administratorsOnly ($policyValue)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 AllocateDASD 값 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '이동식미디어의NTFS포맷및꺼내기가허용되는사용자를관리권한자로제한함으로써관리권한이없는사용자및비인가자에의한불법적인이동식미디어의포맷및이동을차단하기위함'
$threat = '관리자이외사용자에게해당정책이설정된경우비인가자에의한불법적인매체처리를허용할위험존재'
$criteria_good = '''이동식미디어포맷및꺼내기허용''정책이''Administrators''로되어있는경우'
$criteria_bad = '''이동식미디어포맷및꺼내기허용''정책이''Administrators''로되어있지않은경우'
$remediation = '''이동식NTFS미디어꺼내기허용''정책을''Administrators''로설정(로컬보안정책>로컬정책>보안옵션)'

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
