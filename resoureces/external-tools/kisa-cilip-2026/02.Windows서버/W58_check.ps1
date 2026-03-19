# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-58
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 사용자별홈디렉터리권한설정
# @Description : 홈 디렉터리 권한 설정으로 비인가 사용자 정보 노출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-58"
$ITEM_NAME = "사용자별홈디렉터리권한설정"
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

# 1. Check home directory permissions
try {
    $homeDirs = @('C:\Users', 'C:\Documents and Settings')
    $hasEveryone = $false

    foreach ($dir in $homeDirs) {
        if (Test-Path $dir) {
            $acls = Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue
            foreach ($acl in $acls) {
                if ($acl.Name -notin @('All Users', 'Default User', 'Public', 'Default')) {
                    try {
                        $access = Get-Acl $acl.FullName -ErrorAction SilentlyContinue
                        if ($access.AccessToString -match 'Everyone') {
                            $hasEveryone = $true
                            break
                        }
                    } catch {
                        # Ignore access errors
                    }
                }
            }
        }
    }

    if (-not $hasEveryone) {
        $finalResult = "GOOD"
        $summary = "홈 디렉터리에 Everyone 권한이 없음 (적절하게 설정됨)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "홈 디렉터리에 Everyone 권한이 존재함"
        $status = "취약"
    }

    $commandExecuted = "Get-Acl 확인 (C:\Users 또는 C:\Documents and Settings 하위 사용자 디렉터리)"
    $commandOutput = "Everyone 권한 존재: $hasEveryone"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Acl 확인 (C:\Users 또는 C:\Documents and Settings 하위 사용자 디렉터리)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '사용자홈디렉터리에적절한권한을부여하여비인가사용자에의한불필요한정보노출을방지하기위함'
$threat = '사용자계정별홈디렉터리의권한이제한되어있지않으면임의의사용자나다른사용자의홈디렉터리에악의적인목적으로접근할수있으며,접근후의도또는,의도하지않은행위로시스템에악영향을미칠위험존재'
$criteria_good = '홈디렉터리에Everyone권한이없는경우(AllUsers,DefaultUser디렉터리제외)'
$criteria_bad = '홈디렉터리에Everyone권한이있는경우'
$remediation = 'Everyone권한제거(탐색기>사용자폴더우클릭>속성>보안에서Everyone권한제거)'

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
