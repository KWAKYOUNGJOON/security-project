# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-54
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : Dos공격방어레지스트리설정
# @Description : TCP/IP 스택 레지스트리 설정으로 DoS 공격 방어
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-54"
$ITEM_NAME = "Dos공격방어레지스트리설정"
$SEVERITY = "중"
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

# 1. Check DoS protection registry settings
try {
    $tcpipParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction SilentlyContinue

    $synAttackProtect = if ($tcpipParams) { $tcpipParams.SynAttackProtect } else { 0 }
    $enableDeadGWDetect = if ($tcpipParams) { $tcpipParams.EnableDeadGWDetect } else { 1 }
    $keepAliveTime = if ($tcpipParams) { $tcpipParams.KeepAliveTime } else { 7200000 }
    $noNameReleaseOnDemand = if ($tcpipParams) { $tcpipParams.NoNameReleaseOnDemand } else { 0 }

    # Check if all DoS protection settings are properly configured
    $allSet = ($synAttackProtect -ge 1) -and ($enableDeadGWDetect -eq 0) -and ($keepAliveTime -le 300000) -and ($noNameReleaseOnDemand -eq 1)

    if ($allSet) {
        $finalResult = "GOOD"
        $summary = "DoS 방어 레지스트리 4가지 모두 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "DoS 방어 레지스트리가 일부 또는 전체 미설정됨"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' (SynAttackProtect, EnableDeadGWDetect, KeepAliveTime, NoNameReleaseOnDemand)"
    $commandOutput = "SynAttackProtect=$synAttackProtect, EnableDeadGWDetect=$enableDeadGWDetect, KeepAliveTime=$keepAliveTime, NoNameReleaseOnDemand=$noNameReleaseOnDemand"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' (SynAttackProtect, EnableDeadGWDetect, KeepAliveTime, NoNameReleaseOnDemand)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'TCP/IP스택(Stack)을강화하는레지스트리값변경을통하여DoS공격을방어하기위함'
$threat = 'DoS방어레지스트리를설정하지않은경우, DoS공격에의한시스템다운으로서비스제공이중단될위험존재'
$criteria_good = 'SynAttackProtect>=1, EnableDeadGWDetect=0, KeepAliveTime<=300000, NoNameReleaseOnDemand=1 모두설정된경우'
$criteria_bad = 'DoS방어레지스트리값이설정되어있지않은경우'
$remediation = '레지스트리값추가또는수정(HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters)'

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
