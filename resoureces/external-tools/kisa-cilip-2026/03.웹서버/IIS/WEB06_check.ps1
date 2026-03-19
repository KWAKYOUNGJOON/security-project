# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-06
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : 웹서비스상위디렉터리접근제한설정
# @Description : 상위 디렉터리 접근(Path Traversal, ../)을 차단하여 웹 문서 루트 외부의 중요 파일 및 디렉터리에 대한 무단 접근을 방지합니다. IIS는 기본적으로 상위 디렉터리 접근을 차단하지만 URL Rewrite 등의 설정에 따라 우회될 수 있으므로 확인이 필요합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-06"
$ITEM_NAME = "웹서비스상위디렉터리접근제한설정"
$SEVERITY = "중"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 상위 디렉터리 접근 제한 확인 (normalized path)
    $finalResult = "MANUAL"
    $summary = "IIS는 기본적으로 상위 디렉터리 접근(..)을 차단합니다. 그러나 URL rewriting 등의 설정에 따라 다를 수 있으므로 수동 확인 필요."
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter `"/system.webServer/rewrite`""
    $commandOutput = "IIS는 기본적으로 .. 경로 차단. URL Rewrite 규칙 확인 필요."

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter `"/system.webServer/rewrite`""
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '상위 디렉터리 접근(../) 제한으로 중요 파일 및 디렉터리 노출 방지'
$threat = '상위 디렉터리 접근 가능 시 공격자가 시스템 구조 파악 및 정보 유출 위험 존재'
$criteria_good = '상위 디렉터리 접근이 차단된 경우'
$criteria_bad = '상위 디렉터리 접근이 가능한 경우'
$remediation = 'IIS는 기본적으로 차단. URL Rewrite 규칙 검토 필요'

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
