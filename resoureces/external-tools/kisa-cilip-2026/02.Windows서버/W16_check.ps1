

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-16
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 공유권한및사용자그룹설정
# @Description : 공유 폴더 권한 설정 점검으로 Everyone 권한 부여 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-16"
$ITEM_NAME = "공유권한및사용자그룹설정"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check share permissions for Everyone access
try {
    $shares = Get-WmiObject -Class Win32_Share -ErrorAction Stop | Where-Object {
        $_.Name -notlike '*$' -and $_.Name -ne 'ADMIN$' -and $_.Name -ne 'IPC$'
    }

    $vulnerable = $false
    $problemShares = @()

    foreach ($share in $shares) {
        try {
            $security = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$($share.Name)'" -ErrorAction SilentlyContinue
            if ($security) {
                $descriptor = $security.GetSecurityDescriptor()
                $everyoneAccess = $false

                foreach ($ace in $descriptor.Descriptor.DACL) {
                    if ($ace.Trustee.Name -eq 'Everyone' -or $ace.Trustee.Name -eq 'S-1-1-0') {
                        $everyoneAccess = $true
                        break
                    }
                }

                if ($everyoneAccess) {
                    $vulnerable = $true
                    $problemShares += $share.Name
                }
            }
        } catch {
            # Skip shares where security cannot be checked
            continue
        }
    }

    if ($vulnerable) {
        $finalResult = "VULNERABLE"
        $summary = "일반 공유 디렉터리의 접근 권한에 Everyone 권한이 존재: $($problemShares -join ', ')"
        $status = "취약"
        $commandOutput = "Shares with Everyone access: $($problemShares -join ', ')"
    } else {
        $finalResult = "GOOD"
        $summary = "일반 공유 디렉터리가 없거나 공유 권한에 Everyone 권한이 없음"
        $status = "양호"
        $commandOutput = "No shares with Everyone access found"
    }

    $commandExecuted = "Get-WmiObject Win32_Share 및 Win32_LogicalShareSecuritySetting"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동으로 공유 권한 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WmiObject Win32_Share"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '공유 폴더 권한 설정 점검으로 Everyone 권한 부여 방지'
$threat = '공유 폴더에 Everyone 권한 부여 시 비인가자 접근 가능하며 정보 유출 및 악성코드 유포의 접점이 될 수 있음'
$criteria_good = '일반 공유 폴더가 없거나 Everyone 권한이 없는 경우'
$criteria_bad = '일반 공유 폴더에 Everyone 권한이 존재하는 경우'
$remediation = '공유 폴더 속성 > 보안 탭 > Everyone 권한 제거 및 필요한 사용자에게만 적절한 권한 부여'

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
