# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-22
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : 에러페이지관리
# @Description : 기본 에러 페이지(Default Error Pages)를 커스텀 페이지로 변경하여 서버 내부 구조 및 정보 노출을 방지합니다. 기본 에러 페이지 사용 시 서버 버전, 경로 등 민감한 정보가 노출될 수 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-22"
$ITEM_NAME = "에러페이지관리"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS Error Page 확인
    $sites = Get-Website
    $defaultErrorPages = @()
    $defaultPageFound = $false

    foreach ($site in $sites) {
        $siteName = $site.Name

        # Error Pages 설정 확인
        $errorPages = Get-WebConfiguration -Filter "/system.webServer/httpErrors" -Location $siteName -ErrorAction SilentlyContinue
        if ($errorPages) {
            $errorMode = $errorPages.errorMode
            foreach ($error in $errorPages.Collection) {
                $statusCode = $error.statusCode
                $prefix = $error.prefix
                $path = $error.path

                # 기본 에러 페이지 사용 확인
                if ($path -like "%SystemDrive%\inetpub\custerr\*" -or $path -eq "" -or $path -eq $null) {
                    $defaultPageFound = $true
                    $defaultErrorPages += "Site: $siteName, Code: $statusCode, Path: Default IIS error page"
                }
            }
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpErrors'"

    if ($defaultPageFound) {
        $finalResult = "VULNERABLE"
        $summary = "기본 에러 페이지가 사용되고 있습니다: " + ($defaultErrorPages[0] + " 외 " + ($defaultErrorPages.Count - 1) + "개")
        $status = "취약"
        $commandOutput = $defaultErrorPages -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "기본 에러 페이지가 사용되지 않거나 커스텀 에러 페이지가 구성되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Error Pages: Custom pages configured or default pages removed"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpErrors'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '에러 페이지 관리로 서버 내부 구조 및 정보 노출 방지'
$threat = '기본 에러 페이지 사용 시 서버 버전, 경로 등 민감한 정보 노출로 공격자에게 유용한 정보 제공 위험'
$criteria_good = '커스텀 에러 페이지를 사용하거나 기본 에러 페이지의 정보 노출이 제한된 경우'
$criteria_bad = '기본 에러 페이지가 사용되어 서버 정보가 노출되는 경우'
$remediation = 'IIS 관리자 > Error Pages > 기본 에러 페이지를 커스텀 페이지로 변경 또는 DetailedLocalErrors만 사용 (web.config에서 httpErrors errorMode="DetailedLocalOnly")'

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
