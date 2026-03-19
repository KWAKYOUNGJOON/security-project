# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-28
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 터미널서비스암호화수준설정
# @Description : 터미널 서비스 암호화 수준 설정 여부 점검으로 통신 데이터 보호
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-28"
$ITEM_NAME = "터미널서비스암호화수준설정"
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
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $encryptionLevel = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).MinEncryptionLevel

    if ($encryptionLevel) {
        $commandOutput = "MinEncryptionLevel: $encryptionLevel"

        # 암호화 수준: 1=Low(56bit), 2=Medium(128bit), 3=High(256bit), 4=FIPS 140-1
        if ($encryptionLevel -ge 3) {
            $finalResult = "GOOD"
            $summary = "RDP 암호화 수준이 High(Level 3) 이상으로 설정됨"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $encryptionLevelText = if ($encryptionLevel -eq 1) { "Low (56비트)" } elseif ($encryptionLevel -eq 2) { "Medium (128비트)" } else { "Level $encryptionLevel" }
            $summary = "RDP 암호화 수준이 $encryptionLevelText 으로 설정되어 보안 취약"
            $status = "취약"
        }
    } else {
        $finalResult = "VULNERABLE"
        $summary = "RDP 암호화 수준 설정을 찾을 수 없음 (기본값 Low로 취급)"
        $status = "취약"
        $commandOutput = "레지스트리 값 없음 (MinEncryptionLevel)"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel"

# 2. lib를 통한 결과 저장
$purpose = 'RDP 암호화 수준 상향으로 원격 접속 시 데이터 도청 방지'
$threat = '낮은 RDP 암호화 수준 사용 시 네트워크 패킷 감청으로 RDP 세션 정보 탈취 가능'
$criteria_good = '암호화 수준이 High(Level 3) 이상인 경우'
$criteria_bad = '암호화 수준이 Low/Medium인 경우'
$remediation = '레지스트리 편집기에서 MinEncryptionLevel 값 3으로 설정 후 시스템 재시작'

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
