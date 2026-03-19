# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-26
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : RDS(Remote Data Services)제거
# @Description : RDS(Remote Data Services) 서비스/기능 제거로 레거시 데이터 접속 취약점 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-26"
$ITEM_NAME = "RDS(Remote Data Services)제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $rdsService = Get-Service -Name 'MSADC*' -ErrorAction SilentlyContinue
    $commandOutput = ""

    if ($rdsService) {
        $commandOutput = ($rdsService | Format-List -Property Name, Status, StartType | Out-String).Trim()
        $finalResult = "VULNERABLE"
        $summary = "RDS(Remote Data Services) 서비스가 설치되어 있어 보안 위험"
        $status = "취약"
    } else {
        $rdsFeature = Get-WindowsFeature -Name 'RDS-*' -ErrorAction SilentlyContinue | Where-Object { $_.Installed -eq $true }
        if ($rdsFeature) {
            $commandOutput = ($rdsFeature | Format-List -Property Name, DisplayName, Installed | Out-String).Trim()
            $finalResult = "VULNERABLE"
            $summary = "RDS(Remote Data Services) 기능이 설치되어 있어 보안 위험"
            $status = "취약"
        } else {
            $commandOutput = "RDS 서비스 및 기능이 설치되지 않음"
            $finalResult = "GOOD"
            $summary = "RDS(Remote Data Services) 서비스/기능이 설치되지 않음"
            $status = "양호"
        }
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-Service -Name 'MSADC*'; Get-WindowsFeature -Name 'RDS-*'"

# 2. lib를 통한 결과 저장
$purpose = 'RDS(Remote Data Services)는 레거시 데이터 접속 기술로 알려진 보안 취약점이 다수 존재하여 공격 경로로 악용 가능'
$threat = 'RDS 제거를 통해 레거시 데이터 접속 취약점 방지'
$criteria_good = 'RDS 서비스/기능이 설치되지 않은 경우'
$criteria_bad = 'RDS 서비스/기능이 설치된 경우'
$remediation = 'RDS(Remote Data Services) 서비스/기능 제거`n`n방법:`n1. 서비스 제거: Get-Service -Name ''MSADC*'' | Remove-Service -Force`n2. 기능 제거: Remove-WindowsFeature -Name ''RDS-*''`n3. 또는 서버 관리자 > 역할 및 기능 제거'

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
