# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-14
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 하
# @Title       : 웹서비스경로내파일의접근통제
# @Description : 웹서비스 경로 내 백업 파일(.bak), 설정 파일(.config), 소스 코드 등 민감한 파일에 대한 웹 접근을 차단하여 정보 노출을 방지합니다. IIS Request Filtering을 사용하여 파일 확장자별 접근 제어가 필요합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-14"
$ITEM_NAME = "웹서비스경로내파일의접근통제"
$SEVERITY = "하"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 웹서비스 경로 내 불필요한 파일 확인
    $sites = Get-Website
    $sensitiveFiles = @()
    $fileFound = $false

    $sensitivePatterns = @(
        "*.bak",
        "*.old",
        "*.tmp",
        "*.log",
        "*.sql",
        "*.mdb",
        "*.db",
        "*.ini",
        "*.conf",
        "*.config",
        ".git",
        ".svn",
        "*.ps1",
        "*.bat",
        "*.cmd"
    )

    foreach ($site in $sites) {
        $path = $site.PhysicalPath
        if (Test-Path $path) {
            foreach ($pattern in $sensitivePatterns) {
                $files = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    if ($file.FullName -notlike "*\logs\*") {
                        $fileFound = $true
                        $relativePath = $file.FullName.Substring($path.Length)
                        $sensitiveFiles += "Site: $($site.Name), File: $relativePath"
                    }
                }
            }
        }
    }

    $commandExecuted = "Get-Website; Get-ChildItem -Path [SitePath] -Filter *.bak,*.old,*.tmp,*.log,*.sql,*.mdb,*.db,*.ini,*.conf,*.config,.git,.svn,*.ps1,*.bat,*.cmd -Recurse"

    if ($fileFound) {
        $finalResult = "VULNERABLE"
        $summary = "웹서비스 경로 내에 접근이 제한되어야 할 민감한 파일이 발견되었습니다: " + ($sensitiveFiles[0] + " 외 " + ($sensitiveFiles.Count - 1) + "개")
        $status = "취약"
        $commandOutput = $sensitiveFiles -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "웹서비스 경로 내에 노출되면 안되는 민감한 파일이 없습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Sensitive files: Not found in web paths"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-ChildItem -Path [SitePath] -Recurse"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹서비스 경로 내 백업파일, 설정파일 등 민감한 파일의 접근 통제로 정보 노출 방지'
$threat = '백업파일, 설정파일, 소스코드 등이 웹을 통해 접근 가능하면 시스템 정보 노출 및 악용 위험'
$criteria_good = '웹서비스 경로 내의 민감한 파일(.bak, .old, .config 등)에 대한 접근이 차단된 경우'
$criteria_bad = '웹서비스 경로 내의 민감한 파일에 웹을 통해 접근 가능한 경우'
$remediation = 'IIS Request Filtering으로 파일 확장자 차단 또는 웹 경로 외부로 파일 이동 (IIS 관리자 > Request Filtering > File Name Extensions > Deny)'

# 결과 저장
Save-DualResult -ItemId "${ITEM_ID}" `
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

exit 0
