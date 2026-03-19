# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-21
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 암호화되지않는FTP서비스비활성화
# @Description : FTP 서비스 비활성화로 평문 암호 전송 방지 및 데이터 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-21"
$ITEM_NAME = "암호화되지않는FTP서비스비활성화"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check if FTP service is running
try {
    $service = Get-Service -Name 'MSFTPSVC' -ErrorAction SilentlyContinue

    if ($service -and $service.Status -eq 'Running') {
        $finalResult = "VULNERABLE"
        $summary = "FTP 서비스가 실행 중 (평문 암호 전송으로 보안 위험)"
        $status = "취약"
        $commandOutput = "FTP Service Status: $($service.Status)"
    } else {
        $finalResult = "GOOD"
        $summary = "FTP 서비스가 비활성화됨 (또는 중지됨)"
        $status = "양호"
        $commandOutput = if ($service) { "FTP Service Status: $($service.Status)" } else { "FTP Service not installed" }
    }

    $commandExecuted = "Get-Service -Name 'MSFTPSVC'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name 'MSFTPSVC'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'FTP 서비스 비활성화로 평문 암호 전송 방지 및 데이터 유출 방지'
$threat = 'FTP는 암호화되지 않은 프로토콜로 로그인 정보와 데이터가 평문으로 전송되어 패킷 감청 시 계정 정보 및 데이터 유출 위험 존재'
$criteria_good = 'FTP 서비스가 비활성화된 경우'
$criteria_bad = 'FTP 서비스가 활성화된 경우'
$remediation = 'FTP 서비스 중지 및 사용 안 함 설정. FTPS(FTP over SSL/TLS) 사용 권장'

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
