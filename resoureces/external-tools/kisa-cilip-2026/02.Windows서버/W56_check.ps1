# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-56
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : SMB세션중단관리설정
# @Description : SMB 세션 타임아웃 설정으로 서비스 거부 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-56"
$ITEM_NAME = "SMB세션중단관리설정"
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

# 1. Check SMB session timeout settings
try {
    $secedit = secedit /export /cfg "$env:TEMP\secedit.tmp" 2>&1
    $content = Get-Content "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue
    $enableForcedLogoff = 0
    $autoDisconnect = 999999

    if ($content -match 'EnableForcedLogoff\s*=\s*(\d+)') {
        $enableForcedLogoff = [int]$matches[1]
    }

    if ($content -match 'Autodisconnect\s*=\s*(\d+)') {
        $autoDisconnect = [int]$matches[1]
    }

    Remove-Item "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue

    if ($enableForcedLogoff -eq 1 -and $autoDisconnect -le 15) {
        $finalResult = "GOOD"
        $summary = "SMB 세션 타임아웃이 적절하게 설정됨 (15분 이하)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "SMB 세션 타임아웃이 설정되지 않았거나 15분 초과"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 EnableForcedLogoff, Autodisconnect 값 확인"
    $forcedLogoffStatus = switch ($enableForcedLogoff) {
        1 { "사용" }
        0 { "사용안함" }
        default { "알 수 없음 ($enableForcedLogoff)" }
    }
    $commandOutput = "EnableForcedLogoff=$enableForcedLogoff ($forcedLogoffStatus), Autodisconnect=$autoDisconnect 분"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 EnableForcedLogoff, Autodisconnect 값 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'Session연결중단시유휴시간설정여부점검, Session이중단되기전에SMBSession에서보내야하는연속유휴시간을결정하여서비스거부공격등에악용되지않도록하기위함'
$threat = 'SMBSession에서는서버리소스를사용하며, NULLSession수가많으면서버속도가느려지거나서버에오류를발생시킬수있으므로공격자는이를악용하여SMBSession을반복설정하여서버의SMB서비스가느려지거나응답하지않게하여서비스거부공격을실행할위험존재'
$criteria_good = '''로그온시간이만료되면클라이언트연결끊기''정책을''사용''으로,''세션연결을중단하기전에필요한유휴시간''정책을''15분''이하로설정한경우'
$criteria_bad = '''로그온시간이만료되면클라이언트연결끊기''정책이''사용안함''또는''세션연결을중단하기전에필요한유휴시간''정책이''15분''초과로설정한경우'
$remediation = '''로그인시간이만료되면클라이언트연결끊기''정책''사용''설정,''세션연결을중단하기전에필요한유휴시간''정책''15분''이하로설정'

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
