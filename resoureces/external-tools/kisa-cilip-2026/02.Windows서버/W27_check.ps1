# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-27
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 최신Windows OS Build버전적용
# @Description : 최신 Windows OS Build 버전 적용으로 알려진 보안 취약점 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-27"
$ITEM_NAME = "최신Windows OS Build버전적용"
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

# 1. Run diagnostic
try {
    $build = [System.Environment]::OSVersion.Version.Build
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $lastBoot = $osInfo.LastBootUpTime
    $daysSinceBoot = (New-TimeSpan -Start $lastBoot).Days

    $commandOutput = "OS Build: $build`r`nLast Boot: $lastBoot`r`nDays Since Boot: $daysSinceBoot"

    # 최신 빌드 버전 확인 (Windows Server 2022: 20348+, Server 2019: 17763+)
    # 시스템 재시작 후 60일 이내 업데이트 확인
    # 가장 최신 빌드 버전(20348)을 기준으로 확인
    if ($build -ge 20348) {
        if ($daysSinceBoot -gt 60) {
            $finalResult = "VULNERABLE"
            $summary = "최신 OS 빌드이지만 마지막 재시작 후 60일 초과로 최신 보안 업데이트 미적용 가능성"
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "Windows OS가 최신 빌드 버전이며 최근 업데이트됨"
            $status = "양호"
        }
    } else {
        $finalResult = "VULNERABLE"
        $summary = "Windows OS 빌드 버전이 오래되었거나 최신 보안 업데이트 미적용"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "[System.Environment]::OSVersion.Version; Get-CimInstance Win32_OperatingSystem"

# 2. lib를 통한 결과 저장
$purpose = '최신 Windows OS Build 버전 유지로 알려진 보안 취약점 방지'
$threat = '오래된 OS 빌드 사용 시 알려진 취약점으로 인한 공격 위험 존재'
$criteria_good = '최신 OS 빌드 버전이 적용된 경우'
$criteria_bad = '오래된 OS 빌드 버전 사용 중인 경우'
$remediation = 'Windows Update 실행 또는 수동으로 최신 누적 업데이트(Cumulative Update) 설치'

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
