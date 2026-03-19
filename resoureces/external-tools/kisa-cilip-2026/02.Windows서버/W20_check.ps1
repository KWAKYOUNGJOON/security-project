# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-20
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : NetBIOS바인딩서비스구동점검
# @Description : NetBIOS over TCP/IP 비활성화 여부 점검으로 NetBIOS 관련 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-20"
$ITEM_NAME = "NetBIOS바인딩서비스구동점검"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check NetBIOS over TCP/IP settings
try {
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
    $netbiosEnabled = $false
    $adapterDetails = @()

    foreach ($adapter in $adapters) {
        $config = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index=$($adapter.ifIndex)"
        if ($config.TcpipNetbiosOptions -eq 1 -or $config.TcpipNetbiosOptions -eq 0) {
            $netbiosEnabled = $true
            $statusText = switch ($config.TcpipNetbiosOptions) {
                0 { "Enable NetBIOS via DHCP" }
                1 { "Enable NetBIOS" }
                2 { "Disable NetBIOS" }
            }
            $adapterDetails += "$($adapter.Name): $statusText"
        }
    }

    if ($netbiosEnabled) {
        $finalResult = "VULNERABLE"
        $summary = "TCP/IP와 NetBIOS 간의 바인딩이 활성화됨: " + ($adapterDetails -join ', ')
        $status = "취약"
        $commandOutput = $adapterDetails -join '; '
    } else {
        $finalResult = "GOOD"
        $summary = "TCP/IP와 NetBIOS 간의 바인딩이 제거됨 (모든 어댑터에서 NetBIOS 비활성화)"
        $status = "양호"
        $commandOutput = "NetBIOS disabled on all active adapters"
    }

    $commandExecuted = "Get-NetAdapter | Get-WmiObject Win32_NetworkAdapterConfiguration"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-NetAdapter | Get-WmiObject Win32_NetworkAdapterConfiguration"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'NetBIOS over TCP/IP 비활성화 여부 점검으로 NetBIOS 관련 공격 방지'
$threat = 'NetBIOS over TCP/IP 활성화 시 NetBIOS 이름 서포핑 및 정보 유출 공격에 취약하며, 네트워크 스캔으로 시스템 정보 노출 위험 존재'
$criteria_good = 'TCP/IP와 NetBIOS 간의 바인딩이 제거된 경우'
$criteria_bad = 'TCP/IP와 NetBIOS 간의 바인딩이 활성화된 경우'
$remediation = '네트워크 어댑터 속성 > IPv4 > 고급 > WINS 탭 > NetBIOS 설정 '

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
