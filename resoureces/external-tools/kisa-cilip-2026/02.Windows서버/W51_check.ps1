# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-51
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : SAM계정과공유의익명열거허용안함
# @Description : SAM 계정 익명 열거 금지로 악의적인 계정 정보 탈취 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-51"
$ITEM_NAME = "SAM계정과공유의익명열거허용안함"
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

# 1. Check both network access policies as per KISA guideline:
# 1. "네트워크 액세스: SAM 계정과 공유의 익명 열거 허용 안함" (RestrictAnonymous)
# 2. "네트워크 액세스: SAM 계정의 익명 열거 허용 안함" (RestrictAnonymousSAM)
try {
    $secedit = secedit /export /cfg "$env:TEMP\secedit.tmp" 2>&1
    $content = Get-Content "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue
    $restrictAnonymous = 0
    $restrictAnonymousSAM = 0

    if ($content -match 'RestrictAnonymous\s*=\s*(\d+)') {
        $restrictAnonymous = [int]$matches[1]
    }

    if ($content -match 'RestrictAnonymousSAM\s*=\s*(\d+)') {
        $restrictAnonymousSAM = [int]$matches[1]
    }

    Remove-Item "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue

    if ($restrictAnonymous -eq 1 -and $restrictAnonymousSAM -eq 1) {
        $finalResult = "GOOD"
        $summary = "'SAM계정과공유의익명열거허용안함' 정책이 '사용'으로 설정됨 (RestrictAnonymous=1, RestrictAnonymousSAM=1)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'SAM계정과공유의익명열거허용안함' 정책이 '사용안함'으로 설정됨 (RestrictAnonymous 또는 RestrictAnonymousSAM이 1이 아님)"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 레지스트리 HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymous, RestrictAnonymousSAM 확인"
    $commandOutput = "RestrictAnonymous=$restrictAnonymous, RestrictAnonymousSAM=$restrictAnonymousSAM"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 레지스트리 HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymous, RestrictAnonymousSAM 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '익명사용자에의한악의적인계정정보탈취를방지하기위함'
$threat = 'SAM계정과공유의익명열거가허용될경우악의적인사용자가계정이름목록을확인하고이정보를사용하여암호를추측하거나사회공학적공격기법을수행할위험존재'
$criteria_good = '''SAM계정과공유의익명열거허용안함''및''SAM계정의익명열거허용안함''정책이모두''사용''으로설정된경우'
$criteria_bad = '둘중하나라도''사용안함''으로설정된경우'
$remediation = '로컬보안정책>로컬정책>보안옵션에서''네트워크액세스:SAM계정과공유의익명열거허용안함''과''네트워크액세스:SAM계정의익명열거허용안함''을모두''사용''으로설정'

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
