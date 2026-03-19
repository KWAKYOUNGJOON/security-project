

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-16
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 하
# @Title       : 화면보호기대기시간설정및재시작시암호보호설정
# @Description : 화면 보호기 대기 시간 설정 및 재시작 시 암호 보호 기능 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-16"
$ITEM_NAME = "화면보호기대기시간설정및재시작시암호보호설정"
$SEVERITY = "중"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check screensaver settings
try {
    $timeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
    $secure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

    $commandOutput = ""
    $timeoutInfo = ""
    $secureInfo = ""

    if ($timeout -ne $null) {
        $timeoutSeconds = [int]$timeout.ScreenSaveTimeOut
        $timeoutMinutes = [math]::Round($timeoutSeconds / 60, 0)
        $timeoutInfo = "ScreenSaveTimeOut: $timeoutMinutes minutes"
        $commandOutput += $timeoutInfo + "`r`n"
    } else {
        $timeoutInfo = "ScreenSaveTimeOut: Not set"
        $commandOutput += $timeoutInfo + "`r`n"
    }

    if ($secure -ne $null) {
        $secureInfo = "ScreenSaverIsSecure: $($secure.ScreenSaverIsSecure)"
        $commandOutput += $secureInfo + "`r`n"
    } else {
        $secureInfo = "ScreenSaverIsSecure: Not set"
        $commandOutput += $secureInfo + "`r`n"
    }

    $isSecure = $false
    if ($timeout -ne $null -and $secure -ne $null) {
        $timeoutSeconds = [int]$timeout.ScreenSaveTimeOut
        $timeoutMinutes = [math]::Round($timeoutSeconds / 60, 0)
        if ($timeoutMinutes -le 10 -and $secure.ScreenSaverIsSecure -eq 1) {
            $isSecure = $true
        }
    }

    if ($isSecure) {
        $finalResult = "GOOD"
        $summary = "화면보호기 대기시간 10분 이하이고 암호보호 설정됨 ($timeoutInfo, $secureInfo)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        if ($timeout -ne $null -and $secure -ne $null) {
            $timeoutSeconds = [int]$timeout.ScreenSaveTimeOut
            $timeoutMinutes = [math]::Round($timeoutSeconds / 60, 0)
            if ($timeoutMinutes -gt 10) {
                $summary = "화면보호기 대기시간 10분 초과 ($timeoutMinutes분, 암호보호: $($secure.ScreenSaverIsSecure))"
            } else {
                $summary = "화면보호기 암호보호 미설정 (대기시간: $timeoutMinutes분)"
            }
        } else {
            $summary = "화면보호기 설정 안 됨 ($timeoutInfo, $secureInfo)"
        }
        $status = "취약"
    }

    $commandExecuted = "reg query HKCU\Control Panel\Desktop /v ScreenSaveTimeOut /v ScreenSaverIsSecure"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
    $commandExecuted = "reg query HKCU\Control Panel\Desktop"
}

# 2. Define guideline variables
$purpose = '화면보호기 대기시간 설정 및 암호보호로 장기 부재 시 무단 접근 방지'
$threat = '화면보호기 미설정 또는 암호보호 미사용 시 사용자 부재 중 무단 접근 가능하며, 정보 유출 및 악용 위험 존재'
$criteria_good = '대기시간 10분 이하이고 암호보호 설정됨'
$criteria_bad = '대기시간 10분 초과 또는 암호보호 미설정'
$remediation = '개인 설정 > 개인 설정 > 화면 보호기 > 대기 시간 10분 이하 설정, 확인란 암호로 보호 선택'

# 3. Save results using Save-DualResult
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

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
