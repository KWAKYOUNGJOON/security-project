# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-08
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 하
# @Title       : Apache.htaccess오버라이드제한
# @Description : Apache 웹 서버의 .htaccess 파일 오버라이드 기능을 제한하여 설정 파일 무결성을 보장합니다. IIS는 Apache의 .htaccess를 사용하지 않으며 web.config를 사용하므로 이 항목은 IIS에 해당하지 않습니다(N/A).
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-08"
$ITEM_NAME = "Apache.htaccess오버라이드제한"
$SEVERITY = "하"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS는 Apache .htaccess 사용하지 않음
    $finalResult = "N/A"
    $summary = "이 진단 항목은 Apache 대상이며 IIS는 해당하지 않습니다. IIS에서는 URL Rewrite 및 web.config 사용."
    $status = "N/A"
    $commandExecuted = "N/A"
    $commandOutput = "N/A"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "N/A"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'Apache .htaccess 오버라이드 제한으로 설정 파일 무결성성 보장'
$threat = 'Apache는 .htaccess가 비활성화되어야 함. IIS는 해당하지 않음 (web.config 사용)'
$criteria_good = 'Apache만 해당. .htaccess 비활성화된 경우'
$criteria_bad = 'Apache만 해당. .htaccess가 활성화된 경우'
$remediation = 'Apache: AllowOverride None 설정. IIS는 해당하지 않음'

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
