# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-25
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : DNS Zone Transfer설정
# @Description : DNS Zone Transfer 제한으로 DNS 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-25"
$ITEM_NAME = "DNS Zone Transfer설정"
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

# 1. Check DNS Zone Transfer settings
try {
    Import-Module DnsServer -ErrorAction SilentlyContinue

    if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
        $zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq 'Primary' -and $_.IsDsIntegrated -eq $false }
        $hasInsecureTransfer = $false
        $zoneDetails = @()

        foreach ($zone in $zones) {
            $secZone = Get-DnsServerZoneTransferPolicy -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue

            if (-not $secZone -or $secZone.TransferType -eq 'Any') {
                $hasInsecureTransfer = $true
                $transferType = if ($secZone) { $secZone.TransferType } else { "Not configured (defaults to Any)" }
                $zoneDetails += "$($zone.ZoneName): $transferType"
            }
        }

        if ($hasInsecureTransfer) {
            $finalResult = "VULNERABLE"
            $summary = "하나 이상의 DNS Zone에서 모든 호스트로 Zone Transfer 허용"
            $status = "취약"
            $commandOutput = $zoneDetails -join '; '
        } else {
            $finalResult = "GOOD"
            $summary = "DNS Zone Transfer가 제한됨 (특정 서버로만 허용)"
            $status = "양호"
            $primaryZoneCount = ($zones | Measure-Object).Count
            $commandOutput = if ($primaryZoneCount -gt 0) { "All $primaryZoneCount primary non-AD zones have secure transfer policies" } else { "No primary non-AD integrated zones found" }
        }
    } else {
        $finalResult = "GOOD"
        $summary = "DNS Server 역할이 설치되지 않음"
        $status = "양호"
        $commandOutput = "DNS Server role not installed or module not available"
    }

    $commandExecuted = "Get-DnsServerZone | Get-DnsServerZoneTransferPolicy"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-DnsServerZone | Get-DnsServerZoneTransferPolicy"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'DNS Zone Transfer 제한으로 DNS 정보 유출 방지'
$threat = 'Zone Transfer 무제한 허용 시 네트워크 정보 유출 및 공격자 정보 수집 가능'
$criteria_good = 'Zone Transfer가 특정 서버로만 제한된 경우'
$criteria_bad = '모든 호스트로 Zone Transfer 허용된 경우'
$remediation = 'DNS 관리자 > Zone 속성 > Zone Transfer 탭에서 다음 서버에만 선택 후 보조 DNS 서버 IP 입력'

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
