# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-49
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 원격시스템에서강제로시스템종료
# @Description : 원격 시스템 강제 종료 권한 제한으로 서비스 거부 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-49"
$ITEM_NAME = "원격시스템에서강제로시스템종료"
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

# 1. Check remote shutdown privilege
try {
    $tempFile = Join-Path $env:TEMP "secedit_w49.tmp"

    # Export security policy to temp file
    $null = secedit /export /cfg $tempFile 2>&1

    $content = Get-Content $tempFile -ErrorAction Stop
    $remoteShutdown = 0

    # Parse SeRemoteShutdownPrivilege
    if ($content -match 'SeRemoteShutdownPrivilege\s*=\s*(.*)') {
        $privilege = $matches[1].Trim()

        # Check if only Administrators (S-1-5-32-544) have this privilege
        # Format can be: *S-1-5-32-544 or S-1-5-32-544
        if ($privilege -eq '*S-1-5-32-544' -or $privilege -eq 'S-1-5-32-544') {
            $remoteShutdown = 1
        }
    }

    $output = "SeRemoteShutdownPrivilege: $($matches[1])"

    # Clean up temp file
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    if ($remoteShutdown -eq 1) {
        $finalResult = "GOOD"
        $summary = "'원격시스템에서강제로시스템종료' 정책에 'Administrators'만 존재함"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'원격시스템에서강제로시스템종료' 정책에 'Administrators' 외 다른 계정 및 그룹이 존재함"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 SeRemoteShutdownPrivilege 값 확인"
    $commandOutput = $output

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 SeRemoteShutdownPrivilege 값 확인"
    $commandOutput = "진단 실패: $_"

    # Clean up temp file if it exists
    $tempFile = Join-Path $env:TEMP "secedit_w49.tmp"
    Remove-Item $tempFile -ErrorAction SilentlyContinue
}

# 2. lib를 통한 결과 저장
$purpose = '원격에서네트워크를통하여운영체제를종료할수있는사용자나그룹을설정하여특정사용자만시스템종료를허용하기위함'
$threat = '원격시스템강제종료설정이부적절한경우서비스거부공격등에악용될위험존재'
$criteria_good = '"원격시스템에서강제로시스템종료"정책에"Administrators"만존재하는경우'
$criteria_bad = '"원격시스템에서강제로시스템종료"정책에"Administrators"외다른계정및그룹이존재하는경우'
$remediation = '"원격시스템에서강제로시스템종료"정책에"Administrators"외다른계정및그룹제거(로컬보안정책 > 로컬정책 > 사용자권한할당)'

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
