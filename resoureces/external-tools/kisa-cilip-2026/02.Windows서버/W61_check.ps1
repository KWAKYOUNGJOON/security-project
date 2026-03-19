# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-61
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 파일및디렉토리보호
# @Description : NTFS 파일 시스템 사용으로 강화된 보안 기능 및 접근 통제 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-61"
$ITEM_NAME = "파일및디렉토리보호"
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

# 1. Check file system type (NTFS vs FAT)
try {
    $systemDrive = $env:SystemDrive
    $volInfo = fsutil fsinfo volumeinfo $systemDrive 2>&1

    if ($volInfo -match 'File System Name\s*:\s*NTFS') {
        $finalResult = "GOOD"
        $summary = "NTFS 파일 시스템을 사용함"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "FAT 파일 시스템을 사용함 (취약)"
        $status = "취약"
    }

    $commandExecuted = "fsutil fsinfo volumeinfo $systemDrive"
    $commandOutput = $volInfo

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "fsutil fsinfo volumeinfo $env:SystemDrive"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'FAT파일시스템에비해더강화된보안기능을제공하는파일시스템을사용하기위함(파일과디렉터리에소유권과사용권한설정이가능하고ACL을제공)'
$threat = 'FAT파일시스템사용시사용자별접근통제를적용할수없어중요정보에대한책임추적성확보가어려운위험존재'
$criteria_good = 'NTFS파일시스템을사용하는경우'
$criteria_bad = 'FAT파일시스템을사용하는경우'
$remediation = 'FAT파일시스템을사용시가능한NTFS파일시스템변환설정(convert.exe명령어사용)'

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
