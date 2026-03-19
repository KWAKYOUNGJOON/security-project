# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-29
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 불필요한SNMP서비스구동점검
# @Description : 불필요한 SNMP 서비스 구동 여부 점검으로 시스템 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-29"
$ITEM_NAME = "불필요한SNMP서비스구동점검"
$SEVERITY = "중"
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
    $snmpServices = Get-Service -Name 'SNMP*' -ErrorAction SilentlyContinue

    if ($snmpServices) {
        $runningSnmp = $snmpServices | Where-Object { $_.Status -eq 'Running' }

        $serviceList = ($snmpServices | Format-Table -Property Name, Status, StartType -AutoSize | Out-String).Trim()
        $commandOutput = $serviceList

        if ($runningSnmp) {
            $finalResult = "VULNERABLE"
            $summary = "SNMP 서비스가 실행 중 (암호화되지 않은 프로토콜로 보안 위험)"
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "SNMP 서비스가 설치되어 있지만 비활성화됨"
            $status = "양호"
        }
    } else {
        $finalResult = "GOOD"
        $summary = "SNMP 서비스가 설치되지 않음"
        $status = "양호"
        $commandOutput = "SNMP 서비스 없음"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-Service -Name 'SNMP*'"

# 2. lib를 통한 결과 저장
$purpose = '불필요한 SNMP 서비스 비활성화로 암호화되지 않은 정보 유출 방지'
$threat = 'SNMP는 Community String 기반 인증으로 암호화되지 않아 패킷 감청 시 시스템 정보 노출'
$criteria_good = 'SNMP 서비스가 비활성화된 경우'
$criteria_bad = 'SNMP 서비스가 활성화된 경우'
$remediation = '서비스 관리자에서 SNMP 서비스 중지 및 시작 유형을 사용 안 함으로 설정'

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
