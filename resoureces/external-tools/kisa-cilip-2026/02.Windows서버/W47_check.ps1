# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-47
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 하
# @Title       : 화면보호기설정
# @Description : 화면보호기 설정으로 유휴 시간 내 불법적인 시스템 접근 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-47"
$ITEM_NAME = "화면보호기설정"
$SEVERITY = "하"
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

# 1. Check screen saver settings
try {
    $screenSaver = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -ErrorAction Stop
    $scrnsaveexe = if ($screenSaver) { $screenSaver.SCRNSAVE.EXE } else { '' }
    $screenSaveTimeOut = if ($screenSaver) { $screenSaver.ScreenSaveTimeOut } else { 0 }
    $screenSaveIsSecure = if ($screenSaver) { $screenSaver.ScreenSaverIsSecure } else { 0 }

    $output = "SCRNSAVE.EXE: $scrnsaveexe`nScreenSaveTimeOut: $screenSaveTimeOut`nScreenSaverIsSecure: $screenSaveIsSecure"

    # Check if screen saver is configured:
    # - Screen saver executable is set and not empty
    # - Timeout is greater than 0 and less than or equal to 600 seconds (10 minutes)
    # - Password protection is enabled (ScreenSaverIsSecure = 1)
    $isConfigured = ($scrnsaveexe -and $scrnsaveexe.Length -gt 0) -and
                   ($screenSaveTimeOut -gt 0 -and $screenSaveTimeOut -le 600) -and
                   ($screenSaveIsSecure -eq 1)

    if ($isConfigured) {
        $finalResult = "GOOD"
        $summary = "화면보호기가 설정되고 대기시간이 10분(600초) 이하이며 암호 사용이 활성화됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "화면보호기가 설정되지 않았거나 대기시간이 10분 초과 또는 암호 사용이 비활성화됨"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKCU:\Control Panel\Desktop' (SCRNSAVE.EXE, ScreenSaveTimeOut, ScreenSaverIsSecure)"
    $commandOutput = $output

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKCU:\Control Panel\Desktop'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '사용자가일정시간동안아무런작업을수행하지않으면자동으로로그오프되거나워크스테이션이잠기도록설정하여,유휴시간내불법적인시스템접근을차단하기위함'
$threat = '화면보호기설정을하지않으면사용자가자리를비운사이에임의의사용자가해당시스템에접근하여중요정보를유출하거나,악의적인행위를통해시스템운영에악영향을미칠위험존재'
$criteria_good = '화면보호기를설정하고대기시간이10분이하의값으로설정되어있으며,화면보호기해제를위한암호를사용하는경우'
$criteria_bad = '화면보호기가설정되지않거나대기시간이10분초과또는암호사용이비활성화된경우'
$remediation = '화면보호기사용,대기시간10분이하,해제를위한암호사용(개인설정 > 잠금화면또는디스플레이 > 화면보호기설정)'

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
