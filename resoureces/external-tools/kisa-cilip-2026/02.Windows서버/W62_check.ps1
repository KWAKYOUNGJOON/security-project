# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-62
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : 시작프로그램목록분석
# @Description : 시작 프로그램 목록 분석으로 악성 프로그램 실행 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-62"
$ITEM_NAME = "시작프로그램목록분석"
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

# 1. Check startup programs for unusual entries
try {
    $startupPaths = @(
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )

    $hasUnusual = $false

    foreach ($path in $startupPaths) {
        if ($path -like 'HKLM:*' -or $path -like 'HKCU:*') {
            # Registry path
            try {
                $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($items) {
                    $props = Get-Item -Path $path -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
                    if ($props) {
                        foreach ($prop in $props) {
                            if ($prop -notlike '*default*' -and
                                $prop -notlike '*Microsoft*' -and
                                $prop -notlike '*Windows*' -and
                                $prop -notlike '*Intel*' -and
                                $prop -notlike '*AMD*' -and
                                $prop -notlike '*NVIDIA*' -and
                                $prop -notlike '*VMware*') {
                                $hasUnusual = $true
                                break
                            }
                        }
                    }
                }
            } catch {
                # Ignore registry access errors
            }
        } else {
            # File system path
            if (Test-Path $path) {
                $items = Get-ChildItem $path -ErrorAction SilentlyContinue
                if ($items) {
                    foreach ($item in $items) {
                        if ($item.Name -notlike '*desktop.ini' -and $item.Name -notlike '*.lnk') {
                            $hasUnusual = $true
                            break
                        }
                    }
                }
            }
        }
    }

    if (-not $hasUnusual) {
        $finalResult = "GOOD"
        $summary = "시작 프로그램 목록에 불필요하거나 의심스러운 항목이 없음"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "시작 프로그램 목록에 불필요하거나 의심스러운 항목이 존재함"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 및 Get-ChildItem (시작프로그램 경로 및 레지스트리 Run 키 확인)"
    $commandOutput = "불필요한 항목 존재: $hasUnusual"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 및 Get-ChildItem (시작프로그램 경로 및 레지스트리 Run 키 확인)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '불필요한시작프로그램을삭제하거나비활성화하여악의적인공격을차단하기위함'
$threat = 'Windows시작시너무많은시작프로그램이동시에실행되면속도가저하되는문제가발생하며,공격자가심어놓은악성프로그램이나해킹도구가실행되어시스템에피해를줄위험존재'
$criteria_good = '시작프로그램목록을정기적으로검사하고불필요한서비스를비활성화한경우'
$criteria_bad = '시작프로그램목록을정기적으로검사하지않고,부팅시불필요한서비스도실행되고있는경우'
$remediation = '시작프로그램목록의정기적인검사실시및불필요한서비스비활성화설정'

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
