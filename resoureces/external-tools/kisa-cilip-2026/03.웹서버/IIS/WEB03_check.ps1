# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-03
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 상
# @Title       : 비밀번호 파일 권한 관리
# @Description : 비밀번호 파일의 접근 권한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-03"
$ITEM_NAME = "비밀번호파일권한관리"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS는 이 항목이 해당하지 않음 (Tomcat, JEUS 대상)
    $finalResult = "N/A"
    $summary = "이 진단 항목은 Tomcat, JEUS에 적용됩니다. IIS의 경우 Windows 서버 파일 권한 정책(W-10)을 참고하세요."
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
$purpose = '비밀번호 파일의 접근 권한을 제한하여 비인가자의 비밀번호 탈취 방지'
$threat = '비밀번호 파일 권한이 취약할 경우 비인가자가 비밀번호 정보를 획득하여 시스템 장악 위험 존재'
$criteria_good = '비밀번호 파일 권한이 600 또는 640으로 설정된 경우 (Tomcat/JEUS)'
$criteria_bad = '비밀번호 파일 권한이 기준보다 취약한 경우'
$remediation = 'chmod 명령어로 비밀번호 파일 권한 600 또는 640으로 설정 (대상: Tomcat/JEUS)'

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
