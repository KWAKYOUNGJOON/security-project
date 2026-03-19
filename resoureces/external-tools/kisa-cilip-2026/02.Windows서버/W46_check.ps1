# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-46
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : SAM파일접근통제설정
# @Description : SAM 파일 접근 통제로 악의적인 계정 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-46"
$ITEM_NAME = "SAM파일접근통제설정"
$SEVERITY = "상"
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

# 1. Check SAM file access permissions
try {
    $samPath = Join-Path $env:SystemRoot "System32\config\SAM"

    if (-not (Test-Path $samPath)) {
        $finalResult = "MANUAL"
        $summary = "SAM 파일을 찾을 수 없거나 진단 실패: 수동 확인 필요"
        $status = "수동진단"
        $commandExecuted = "Get-Acl $samPath"
        $commandOutput = "SAM 파일을 찾을 수 없음"
    } else {
        $acl = Get-Acl $samPath -ErrorAction Stop
        $access = $acl.AccessToString
        $hasUnauthorized = $false

        foreach ($line in $access.Split("`n")) {
            # Skip if it's BUILTIN\Administrators or NT AUTHORITY\SYSTEM
            if ($line -match 'BUILTIN\\Administrators' -or $line -match 'NT AUTHORITY\\SYSTEM') {
                continue
            } else {
                # Check if any other account has Allow + FullControl
                if ($line -match 'Allow' -and $line -match 'FullControl') {
                    $hasUnauthorized = $true
                    break
                }
            }
        }

        if (-not $hasUnauthorized) {
            $finalResult = "GOOD"
            $summary = "SAM 파일 접근 권한에 Administrator, System 그룹만 모든 권한으로 설정됨"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "SAM 파일 접근 권한에 Administrator, System 그룹 외 다른 그룹에 권한이 설정됨"
            $status = "취약"
        }

        $commandExecuted = "Get-Acl $samPath"
        $commandOutput = $access
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "SAM 파일을 찾을 수 없거나 진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Acl $samPath"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'Administrator및System그룹만SAM파일에접근할수있도록제한하여악의적인계정정보유출을차단하기위함'
$threat = 'SAM파일이노출될경우비밀번호공격시도로인해계정및비밀번호데이터베이스정보가탈취될위험존재'
$criteria_good = 'SAM파일접근권한에Administrator,System그룹만모든권한으로설정된경우'
$criteria_bad = 'SAM파일접근권한에Administrator,System그룹외다른그룹에권한이설정된경우'
$remediation = 'SAM파일권한확인후Administrator,System그룹외다른그룹에설정된권한제거(%systemroot%\system32\config\SAM > 속성 > 보안)'

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
