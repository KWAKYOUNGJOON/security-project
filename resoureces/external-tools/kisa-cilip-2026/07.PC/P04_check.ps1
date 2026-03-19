

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-04
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 공유폴더제거
# @Description : 시스템의 공유폴더를 제거하여 외부 접근 경로 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-04"
$ITEM_NAME = "공유폴더제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'net share; Get-SmbShareAccess'
$commandOutput = ""
try {
    $shareOutput = net share 2>&1 | Out-String
    $commandOutput = $shareOutput
    $lines = $shareOutput -split '`r`?`n'
    $basicShares = @('C$', 'ADMIN$', 'IPC$', 'print$')
    $unnecessaryShares = @()
    $everyoneAccessShares = @()

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line -match '[가-힣]' -or $line -match '^-{10,}') {
            continue
        }
        if ($line -match '^([A-Za-z\$][A-Za-z0-9\$\-_]*)\s+') {
            $shareName = $matches[1]
            if ($shareName -notin $basicShares) {
                $unnecessaryShares += $shareName

                # Check Everyone access for this share
                try {
                    $accessCheck = Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue
                    foreach ($access in $accessCheck) {
                        if ($access.AccountName -eq 'Everyone' -or $access.AccountName -like '*S-1-1-0') {
                            if ($access.AccessControlType -eq 'Allow') {
                                $everyoneAccessShares += "$shareName ($($access.AccessRight))"
                            }
                        }
                    }
                } catch {
                    # PowerShell 5.1 compatibility: use net share with access check
                    $shareDetail = net share $shareName 2>&1 | Out-String
                    if ($shareDetail -match 'Everyone') {
                        $everyoneAccessShares += "$shareName (access suspected)"
                    }
                }
            }
        }
    }

    if ($unnecessaryShares.Count -eq 0) {
        $finalResult = "GOOD"
        $unnecessaryList = "(없음)"
        $summary = "불필요한 공유 폴더가 존재하지 않음 (기본 공유 C$, ADMIN$, IPC$, print$만 존재)"
        $status = "양호"
    } elseif ($everyoneAccessShares.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $unnecessaryList = $unnecessaryShares -join ', '
        $everyoneList = $everyoneAccessShares -join ', '
        $summary = "불필요한 공유 폴더 존재 + Everyone 권한: $unnecessaryList`nEveryone 권한 있는 공유: $everyoneList"
        $status = "취약"
    } else {
        $finalResult = "VULNERABLE"
        $unnecessaryList = $unnecessaryShares -join ', '
        $summary = "불필요한 공유 폴더 존재: $unnecessaryList (Everyone 권한 없음)"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $unnecessaryList = "진단 실패"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '불필요한 공유 폴더를 제거하고 Everyone 권한을 제한하여 인가되지 않은 사용자의 중요정보 접근 차단'
$threat = '공유 폴더에 Everyone 권한이 있는 경우 인가되지 않은 사용자가 중요정보에 접근 가능하여 정보유출 위험'
$criteria_good = '불필요한 공유 폴더가 없거나 Everyone 권한이 제거된 경우'
$criteria_bad = '불필요한 공유 폴더가 존재하거나 Everyone 권한이 부여된 경우'
$remediation = '1. net share [공유명] /delete 명령으로 불필요한 공유 제거`n2. 공유 폴더 속성 > 보안 > Everyone 그룹 제거 또는 권한 거부'

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
