# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-09
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 상
# @Title       : 웹서비스프로세스권한제한
# @Description : 웹 서비스 프로세스(IIS Application Pool)가 관리자 권한(LocalSystem, Administrator)이 아닌 최소 권한(ApplicationPoolIdentity, IIS AppPool 계정 등)으로 실행되도록 제한합니다. 웹 프로세스가 관리자 권한으로 실행될 경우 취약점 악용 시 시스템 전체 권한 탈취 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-09"
$ITEM_NAME = "웹서비스프로세스권한제한"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS AppPool Identity 확인
    $appPools = Get-WebApplicationPool
    $rootAppPools = @()
    $vulnerableFound = $false

    foreach ($pool in $appPools) {
        $poolName = $pool.Name
        $identity = $pool.ProcessModel.IdentityType
        $userName = $pool.ProcessModel.UserName

        if ($identity -eq "LocalSystem" -or $identity -eq "0") {
            # LocalSystem 또는 ApplicationPoolIdentity
            $vulnerableFound = $true
            $rootAppPools += "Pool: $poolName, Identity: $identity (권장 권한)"
        } elseif ($userName -eq "Administrator" -or $userName -eq "DOMAIN\Administrator") {
            $vulnerableFound = $true
            $rootAppPools += "Pool: $poolName, User: $userName (관리자 권한)"
        } else {
            $rootAppPools += "Pool: $poolName, User: $userName (적절)"
        }
    }

    $commandExecuted = "Get-WebApplicationPool | Select-Object Name, ProcessModel"

    if ($vulnerableFound) {
        $finalResult = "VULNERABLE"
        $summary = "하나 이상의 AppPool이 관리자 권한(LocalSystem, Administrator)으로 실행 중입니다: " + ($rootAppPools -join ", ")
        $status = "취약"
        $commandOutput = $rootAppPools -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "모든 AppPool이 일반 사용자 권한(ApplicationPoolIdentity, NetworkService, LocalService 등)으로 실행 중입니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = $rootAppPools -join "`n"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebApplicationPool | Select-Object Name, ProcessModel"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹서비스 프로세스가 관리자 권한이 아닌 최소 권한으로 구동되도록 제한'
$threat = '웹 프로세스가 관리자 권한으로 구동 시 취약점 악용 시 시스템 권한 탈취 위험'
$criteria_good = '웹 프로세스가 관리자 권한이 아닌 별도 계정으로 구동 (ApplicationPoolIdentity, IIS AppPool 계정 등)'
$criteria_bad = '웹 프로세스가 LocalSystem, Administrator 권한으로 구동'
$remediation = 'IIS 관리자 > Application Pools > Advanced > Process Model > Identity > ApplicationPoolIdentity 또는 NetworkService 등 일반 계정으로 변경'

# 결과 저장
Save-DualResult -ItemId "${ITEM_ID}" `
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

exit 0
