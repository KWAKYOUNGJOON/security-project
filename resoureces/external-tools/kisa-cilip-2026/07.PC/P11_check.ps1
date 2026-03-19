

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-11
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 최신보안패치및벤더권고사항적용WindowsOSBuild점검
# @Description : 최신 보안 패치 및 벤더 권고 사항 적용 및 Windows OS Build 버전 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-11"
$ITEM_NAME = "최신보안패치및벤더권고사항적용WindowsOSBuild점검"
$SEVERITY = "상"
$CATEGORY = "3.패치관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $command = 'Get-CimInstance Win32_OperatingSystem'
    $os = Get-CimInstance Win32_OperatingSystem
    $caption = $os.Caption
    $build = [int]$os.BuildNumber

    $displayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
    $releaseId = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ReleaseId

    $commandResult = "OS: $caption | Build: $build"
    if ($displayVersion) { $commandResult += " | DisplayVersion: $displayVersion" }
    if ($releaseId) { $commandResult += " | ReleaseId: $releaseId" }

    if ($build -ge 22000) {
        $finalResult = "GOOD"
        $summary = "Windows 11 Build $build - 최신 지원 버전 사용 중"
        $status = "양호"
    } elseif ($build -ge 19044) {
        $finalResult = "GOOD"
        $summary = "Windows 10 Build $build 이상 지원"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "Windows 10 Build $build 미지원 버전"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandResult = $_.Exception.Message
}

# 2. Define guideline variables
$purpose = '최신 Windows OS Build 사용으로 지원 종료 및 패치 미누락 방지, 최신 보안 기능 활용'
$threat = '지원 종료된 Windows OS 사용 시 보안 패치가 중단되어 알려진 취약점 공격 가능성 높으며, 제로데이 공격 등 악용 위험 심각'
$criteria_good = 'Windows 10 Build 19044 이상(21H2, 22H2) 또는 Windows 11 모든 Build 사용'
$criteria_bad = 'Windows 10 Build 19044 미만(지원 종료 버전) 사용'
$remediation = 'Windows 10 21H2 이상 또는 Windows 11로 업그레이드. Windows Update 설정에서 최신 기능 업데이트 설치'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandResult `
    -CommandExecuted $command `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
