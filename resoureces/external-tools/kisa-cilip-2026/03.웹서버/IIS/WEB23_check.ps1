# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-23
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : HTTP메서드제한
# @Description : 불필요한 HTTP 메서드(PUT, DELETE, TRACE, OPTIONS, CONNECT, PATCH)를 제한하여 서버 파일 변조 및 정보 노출을 방지합니다. 불필요한 HTTP 메서드 허용 시 파일 업로드, 삭제, 수정 및 Cross-Site Tracing 공격이 가능합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-23"
$ITEM_NAME = "HTTP메서드제한"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS HTTP Method 제한 확인
    $sites = Get-Website
    $unrestrictedMethods = @()
    $methodIssueFound = $false

    # 제한 필요한 HTTP 메서드
    $unsafeMethods = @("PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH")

    foreach ($site in $sites) {
        $siteName = $site.Name

        # Request Filtering의 HTTP 메서드 제한 확인
        $requestFiltering = Get-WebConfiguration -Filter "/system.webServer/security/requestFiltering" -Location $siteName -ErrorAction SilentlyContinue
        if ($requestFiltering) {
            $verbs = $requestFiltering.verbs
            if ($verbs) {
                $allowedVerbs = @()
                $deniedVerbs = @()

                foreach ($verb in $verbs.Collection) {
                    if ($verb.allowed -eq "true") {
                        $allowedVerbs += $verb.verb
                    } else {
                        $deniedVerbs += $verb.verb
                    }
                }

                # 안전하지 않은 메서드가 허용되어 있는지 확인
                foreach ($unsafeMethod in $unsafeMethods) {
                    if ($allowedVerbs -contains $unsafeMethod -or $allowedVerbs -contains "*") {
                        $methodIssueFound = $true
                        $unrestrictedMethods += "Site: $siteName, Unsafe Method: $unsafeMethod (Allowed)"
                    }
                }

                # 명시적인 제한이 없는 경우
                if ($allowedVerbs.Count -eq 0 -and $deniedVerbs.Count -eq 0) {
                    $methodIssueFound = $true
                    $unrestrictedMethods += "Site: $siteName, HTTP Methods: No restrictions configured"
                }
            } else {
                $methodIssueFound = $true
                $unrestrictedMethods += "Site: $siteName, HTTP Methods: No verb restrictions configured"
            }
        } else {
            $methodIssueFound = $true
            $unrestrictedMethods += "Site: $siteName, Request Filtering: Not configured"
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering/verbs'"

    if ($methodIssueFound) {
        $finalResult = "VULNERABLE"
        $summary = "불필요한 HTTP 메서드가 제한되지 않고 있습니다: " + ($unrestrictedMethods[0] + " 외 " + ($unrestrictedMethods.Count - 1) + "개")
        $status = "취약"
        $commandOutput = $unrestrictedMethods -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "불필요한 HTTP 메서드가 적절히 제한되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "HTTP Methods: Restricted (GET, POST, HEAD only recommended)"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering/verbs'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '불필요한 HTTP 메서드(PUT, DELETE, TRACE 등) 제한으로 서버 파일 변조 및 정보 노출 방지'
$threat = '불필요한 HTTP 메서드 허용 시 공격자가 파일 업로드, 삭제, 수정 및 Cross-Site Tracing 공격 가능'
$criteria_good = '필요한 HTTP 메서드(GET, POST, HEAD)만 허용하고 불필요한 메서드는 차단된 경우'
$criteria_bad = 'PUT, DELETE, TRACE 등 불필요한 HTTP 메서드가 허용된 경우'
$remediation = 'IIS 관리자 > Request Filtering > HTTP Verbs > 불필요한 메서드(Deny) 추가 (TRACE, PUT, DELETE, OPTIONS, CONNECT 등)'

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
