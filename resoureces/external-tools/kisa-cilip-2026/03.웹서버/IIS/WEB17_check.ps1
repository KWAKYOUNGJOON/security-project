# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-17
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : 웹서비스가상디렉토리삭제
# @Description : 불필요한 가상 디렉터리(Virtual Directories)를 삭제하여 디렉터리 트래버설 공격 및 정보 노출을 방지합니다. 불필요한 가상 디렉터리 존재 시 공격자가 예상치 못한 경로로 접근하여 정보 유출이 가능합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-17"
$ITEM_NAME = "웹서비스가상디렉토리삭제"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 가상 디렉터리 확인
    $sites = Get-Website
    $virtualDirs = @()
    $unnecessaryVDirs = @()

    foreach ($site in $sites) {
        $siteName = $site.Name

        # 가상 디렉터리 확인
        $vDirs = Get-WebVirtualDirectory -Site $siteName
        foreach ($vDir in $vDirs) {
            $path = $vDir.Path
            $physicalPath = $vDir.PhysicalPath

            # 기본 경로가 아닌 외부 경로 확인
            if ($physicalPath -like "*\*" -or $physicalPath -notlike "*$($site.PhysicalPath)*") {
                $unnecessaryVDirs += "Site: $siteName, Virtual Path: $path, Physical Path: $physicalPath"
            }
        }
    }

    $commandExecuted = "Get-Website; Get-WebVirtualDirectory -Site [SiteName]"

    if ($unnecessaryVDirs.Count -gt 0) {
        $finalResult = "MANUAL"
        $summary = "가상 디렉터리가 발견되었습니다: " + ($unnecessaryVDirs -join ", ") + " - 불필요한지 수동 확인 필요."
        $status = "수동진단"
        $commandOutput = $unnecessaryVDirs -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "불필요한 가상 디렉터리가 발견되지 않았습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Virtual Directories: None found"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebVirtualDirectory -Site [SiteName]"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '불필요한 가상 디렉터리 삭제로 디렉터리 트래버설 공격 및 정보 노출 방지'
$threat = '불필요한 가상 디렉터리 존재 시 공격자가 예상치 못한 경로로 접근하여 정보 유출 가능'
$criteria_good = '불필요한 가상 디렉터리가 삭제된 경우'
$criteria_bad = '사용하지 않는 가상 디렉터리가 존재하는 경우'
$remediation = 'IIS 관리자 > 해당 사이트 > 가상 디렉토리 선택 > 제거 (사용하지 않는 가상 디렉터리 삭제)'

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
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
