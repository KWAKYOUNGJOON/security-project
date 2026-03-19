

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-18
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 불필요한서비스제거
# @Description : 불필요한 서비스 실행 여부 점검으로 시스템 자원 낭비 방지 및 공격 표면 감소
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-18"
$ITEM_NAME = "불필요한서비스제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check unnecessary services
try {
    $unnecessaryServices = @('Alerter', 'Clipbook', 'Messenger', 'Remote Registry', 'Simple TCP/IP Services')
    $runningServices = @()

    foreach ($svcName in $unnecessaryServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                $runningServices += $svcName
            }
        } catch {
            # Service not found or error, skip
            continue
        }
    }

    if ($runningServices.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "불필요한 서비스가 모두 중지됨"
        $status = "양호"
        $commandOutput = "All unnecessary services are stopped or not installed"
    } else {
        $finalResult = "VULNERABLE"
        $runningList = $runningServices -join ', '
        $summary = "불필요한 서비스가 구동 중임: $runningList"
        $status = "취약"
        $commandOutput = "Running unnecessary services: $runningList"
    }

    $commandExecuted = "Get-Service -Name 'Alerter','Clipbook','Messenger','Remote Registry','Simple TCP/IP Services'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name '...'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '불필요한 서비스 실행 여부 점검으로 시스템 자원 낭비 방지 및 공격 표면 감소'
$threat = '불필요한 서비스 실행 시 시스템 자원 낭비 및 해당 서비스 취약점으로 인한 공격 위험 존재'
$criteria_good = '불필요한 서비스가 모두 중지된 경우'
$criteria_bad = '불필요한 서비스가 실행 중인 경우'
$remediation = 'services.msc > 불필요한 서비스 속성 > 시작 유형 > 사용 안 함 또는 수동으로 변경 후 서비스 중지'

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
