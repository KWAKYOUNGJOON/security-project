# KISA 취약점 진단 시스템 - 결과 관리자 (PowerShell)
# Encoding: UTF-8, CRLF
# Purpose: 진단 결과 파일 생성, 저장, 관리 (IIS 전용)
# Platform: Windows Server, IIS

#Requires -Version 5.1


# UTF-8 인코딩 설정 (한글 출력 지원)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
# 결과 디렉토리 기본 경로
$SCRIPT:RESULT_DIR_BASE = "results"
$SCRIPT:DATE_SUFFIX = (Get-Date).ToString("yyyyMMdd")
$SCRIPT:TIMESTAMP = (Get-Date).ToString("yyyyMMdd_HHmmss")

# ============================================================================
# 헬퍼 함수
# ============================================================================

# 호스트네임 가져오기
function Get-Hostname {
    return [System.Net.Dns]::GetHostName()
}

# 디스크 공간 확인 (MB 단위)
function Test-DiskSpace {
    param(
        [string]$Path = ".",
        [int]$RequiredMB = 100
    )

    $drive = (Get-Item $Path).PSDrive.Name
    $driveInfo = Get-PSDrive -Name $drive
    $freeMB = [math]::Floor($driveInfo.Free / 1MB)

    if ($freeMB -lt $RequiredMB) {
        Write-Warning "디스크 공간 부족: ${freeMB}MB 남음 (필요: ${RequiredMB}MB)"
        return $false
    }

    return $true
}

# Run-all 모드 확인 (모든 PowerShell 카테고리 지원)
# Unix와 동일한 패턴: 단일 함수로 모든 카테고리의 run_all 모드 감지
function Test-RunallMode {
    # 향후 표준: POWERSHELL_RUNALL_MODE 사용 권장
    # 하위 호환성: 기존 환경 변수들도 지원 (WS/PC/WINDOWS_RUNALL_MODE)
    return ($env:POWERSHELL_RUNALL_MODE -eq "1" -or
            $env:WS_RUNALL_MODE -eq "1" -or
            $env:PC_RUNALL_MODE -eq "1" -or
            $env:WINDOWS_RUNALL_MODE -eq "1" -or
            $env:DBMS_RUNALL_MODE -eq "1")
}

# ============================================================================
# 결과 파일 경로 생성
# ============================================================================

function New-ResultFilePath {
    param(
        [string]$ItemId,
        [string]$ScriptDir = $SCRIPT_DIR
    )

    $platformDir = Join-Path $ScriptDir "$RESULT_DIR_BASE\$DATE_SUFFIX"
    $hostname = Get-Hostname

    # 날짜별 폴더 생성 (results/YYYYMMDD/ 구조)
    if (-not (Test-Path $platformDir)) {
        New-Item -ItemType Directory -Path $platformDir -Force | Out-Null
    }

    # 결과 파일 경로 반환: {HOSTNAME}_{ITEM_ID}_result_{YYYYMMDD}_{HHMMSS}
    $baseName = "${hostname}_${ItemId}_result_${TIMESTAMP}"
    return @{
        BasePath = $platformDir
        BaseName = $baseName
        JsonPath = Join-Path $platformDir "${baseName}.json"
        TxtPath = Join-Path $platformDir "${baseName}.txt"
    }
}

# ============================================================================
# JSON 내용만 생성 (mode check 없음)
# ============================================================================

function Generate-JsonContent {
    param(
        [string]$ItemId,
        [string]$ItemName,
        [string]$Status,
        [string]$FinalResult,
        [string]$InspectionSummary,
        [string]$CommandResult,
        [string]$CommandExecuted,
        [string]$GuidelinePurpose,
        [string]$GuidelineThreat,
        [string]$GuidelineCriteriaGood,
        [string]$GuidelineCriteriaBad,
        [string]$GuidelineRemediation
    )

    # command_result를 JSON 문자열로 이스케이프
    $escapedResult = $CommandResult -replace '\\', '\\' -replace '"', '\"' -replace "`n", '\n' -replace "`r", '\r'

    $json = @{
        item_id = $ItemId
        item_name = $ItemName
        inspection = @{
            summary = $InspectionSummary
            status = $Status
        }
        final_result = $FinalResult
        command = $CommandExecuted
        command_result = $escapedResult
        guideline = @{
            purpose = $GuidelinePurpose
            security_threat = $GuidelineThreat
            judgment_criteria_good = $GuidelineCriteriaGood
            judgment_criteria_bad = $GuidelineCriteriaBad
            remediation = $GuidelineRemediation
        }
        timestamp = (Get-Date).ToString("o")
        hostname = (Get-Hostname)
    }

    return ($json | ConvertTo-Json -Depth 3)
}

# ============================================================================
# JSON 결과 생성 및 저장
# ============================================================================

function Save-JsonResult {
    param(
        [string]$ItemId,
        [string]$ItemName,
        [string]$Status,
        [string]$FinalResult,
        [string]$InspectionSummary,
        [string]$CommandResult,
        [string]$CommandExecuted,
        [string]$GuidelinePurpose,
        [string]$GuidelineThreat,
        [string]$GuidelineCriteriaGood,
        [string]$GuidelineCriteriaBad,
        [string]$GuidelineRemediation
    )

    $jsonContent = Generate-JsonContent -ItemId $ItemId `
        -ItemName $ItemName `
        -Status $Status `
        -FinalResult $FinalResult `
        -InspectionSummary $InspectionSummary `
        -CommandResult $CommandResult `
        -CommandExecuted $CommandExecuted `
        -GuidelinePurpose $GuidelinePurpose `
        -GuidelineThreat $GuidelineThreat `
        -GuidelineCriteriaGood $GuidelineCriteriaGood `
        -GuidelineCriteriaBad $GuidelineCriteriaBad `
        -GuidelineRemediation $GuidelineRemediation

    # Run-all 모드: stdout으로 JSON만 출력, 파일 생성 안함
    if (Test-RunallMode) {
        Write-Output $jsonContent
        return
    }

    # 개별 실행 모드: 파일로 저장
    $paths = New-ResultFilePath -ItemId $ItemId
    $jsonContent | Out-File -FilePath $paths.JsonPath -Encoding UTF8 -Force

    # JSON 유효성 검증
    try {
        $null = $jsonContent | ConvertFrom-Json
    } catch {
        Write-Error "❌ 치명적 오류: JSON 유효성 검증 실패"
        Write-Error "파일: $($paths.JsonPath)"
        throw
    }

    return $paths.JsonPath
}

# ============================================================================
# 텍스트 결과 생성 및 저장 (output_format.ps1 사용)
# ============================================================================

function Save-TextResult {
    <#
    .SYNOPSIS
        텍스트 결과 생성 및 저장

    .DESCRIPTION
        output_format.ps1의 New-TextResultContent를 사용하여
        텍스트 결과를 생성하고 저장합니다.

    .PARAMETER ItemId
        진단 항목 ID

    .PARAMETER ItemName
        진단 항목 이름

    .PARAMETER Status
        진단 상태 (양호/취약/수동진단/N/A)

    .PARAMETER FinalResult
        최종 결과 (GOOD/VULNERABLE/MANUAL/N/A)

    .PARAMETER InspectionSummary
        진단 요약

    .PARAMETER CommandResult
        명령 실행 결과

    .PARAMETER CommandExecuted
        실행한 명령

    .PARAMETER GuidelinePurpose
        진단 목적

    .PARAMETER GuidelineThreat
        보안 위협

    .PARAMETER GuidelineCriteriaGood
        양호 기준

    .PARAMETER GuidelineCriteriaBad
        취약 기준

    .PARAMETER GuidelineRemediation
        조치 방법

    .RETURNS
        String - TXT 파일 경로
    #>
    param(
        [string]$ItemId,
        [string]$ItemName,
        [string]$Status,
        [string]$FinalResult,
        [string]$InspectionSummary,
        [string]$CommandResult,
        [string]$CommandExecuted,
        [string]$GuidelinePurpose,
        [string]$GuidelineThreat,
        [string]$GuidelineCriteriaGood,
        [string]$GuidelineCriteriaBad,
        [string]$GuidelineRemediation
    )

    $paths = New-ResultFilePath -ItemId $ItemId

    # output_format.ps1에서 텍스트 내용 생성 (중앙 관리되는 템플릿 사용)
    $libDir = Join-Path $PSScriptRoot "output_format.ps1"
    . $libDir

    $txtLines = New-TextResultContent -ItemId $ItemId `
        -ItemName $ItemName `
        -InspectionSummary $InspectionSummary `
        -CommandResult $CommandResult `
        -CommandExecuted $CommandExecuted `
        -FinalResult $FinalResult `
        -GuidelinePurpose $GuidelinePurpose `
        -GuidelineThreat $GuidelineThreat `
        -GuidelineCriteriaGood $GuidelineCriteriaGood `
        -GuidelineCriteriaBad $GuidelineCriteriaBad `
        -GuidelineRemediation $GuidelineRemediation

    # 파일 저장
    $txtLines | Out-File -FilePath $paths.TxtPath -Encoding UTF8 -Force

    return $paths.TxtPath
}

# ============================================================================
# 이중 결과 생성 및 저장 (JSON + TXT)
# ============================================================================

function Save-DualResult {
    param(
        [string]$ItemId,
        [string]$ItemName,
        [string]$Status,
        [string]$FinalResult,
        [string]$InspectionSummary,
        [string]$CommandResult,
        [string]$CommandExecuted,
        [string]$GuidelinePurpose,
        [string]$GuidelineThreat,
        [string]$GuidelineCriteriaGood,
        [string]$GuidelineCriteriaBad,
        [string]$GuidelineRemediation,
        [string]$ScriptDir = $SCRIPT_DIR
    )

    # Run-all 모드: JSON만 stdout로 출력
    if (Test-RunallMode) {
        $jsonContent = Generate-JsonContent -ItemId $ItemId `
            -ItemName $ItemName `
            -Status $Status `
            -FinalResult $FinalResult `
            -InspectionSummary $InspectionSummary `
            -CommandResult $CommandResult `
            -CommandExecuted $CommandExecuted `
            -GuidelinePurpose $GuidelinePurpose `
            -GuidelineThreat $GuidelineThreat `
            -GuidelineCriteriaGood $GuidelineCriteriaGood `
            -GuidelineCriteriaBad $GuidelineCriteriaBad `
            -GuidelineRemediation $GuidelineRemediation

        Write-Output $jsonContent
        return
    }

    # 개별 실행 모드: JSON + TXT 파일 생성
    $jsonPath = Save-JsonResult -ItemId $ItemId `
        -ItemName $ItemName `
        -Status $Status `
        -FinalResult $FinalResult `
        -InspectionSummary $InspectionSummary `
        -CommandResult $CommandResult `
        -CommandExecuted $CommandExecuted `
        -GuidelinePurpose $GuidelinePurpose `
        -GuidelineThreat $GuidelineThreat `
        -GuidelineCriteriaGood $GuidelineCriteriaGood `
        -GuidelineCriteriaBad $GuidelineCriteriaBad `
        -GuidelineRemediation $GuidelineRemediation

    $txtPath = Save-TextResult -ItemId $ItemId `
        -ItemName $ItemName `
        -Status $Status `
        -FinalResult $FinalResult `
        -InspectionSummary $InspectionSummary `
        -CommandResult $CommandResult `
        -CommandExecuted $CommandExecuted `
        -GuidelinePurpose $GuidelinePurpose `
        -GuidelineThreat $GuidelineThreat `
        -GuidelineCriteriaGood $GuidelineCriteriaGood `
        -GuidelineCriteriaBad $GuidelineCriteriaBad `
        -GuidelineRemediation $GuidelineRemediation

    return @{
        JsonPath = $jsonPath
        TxtPath = $txtPath
    }
}

# ============================================================================
# 결과 저장 확인
# ============================================================================

function Test-ResultSaved {
    param(
        [string]$ItemId
    )

    $paths = New-ResultFilePath -ItemId $ItemId

    if (-not (Test-Path $paths.JsonPath)) {
        Write-Error "❌ JSON 결과 파일 생성 실패: $($paths.JsonPath)"
        return $false
    }

    if (-not (Test-Path $paths.TxtPath)) {
        Write-Error "❌ TXT 결과 파일 생성 실패: $($paths.TxtPath)"
        return $false
    }

    return $true
}

# ============================================================================
# UI 헬퍼 함수
# ============================================================================

function Show-DiagnosisStart {
    param(
        [string]$ItemId,
        [string]$ItemName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Host '============================================================'
    Write-Host "진단 시작: $ItemId - $ItemName"
    Write-Host "시간: $timestamp"
    Write-Host '============================================================'
}

function Show-DiagnosisComplete {
    param(
        [string]$ItemId,
        [string]$FinalResult = "UNKNOWN"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Host ''
    Write-Host '============================================================'
    Write-Host "진단 완료: $ItemId - 결과: $FinalResult"
    Write-Host "시간: $timestamp"
    Write-Host '============================================================'
}

function Confirm-ResultSaved {
    param(
        [string]$ItemId
    )

    $paths = New-ResultFilePath -ItemId $ItemId

    if ((Test-Path $paths.JsonPath) -and (Test-Path $paths.TxtPath)) {
        $jsonSize = (Get-Item $paths.JsonPath).Length
        $txtSize = (Get-Item $paths.TxtPath).Length
        Write-Host "결과 파일 저장 확인: $($paths.BasePath)\$($paths.BaseName).{json,txt}"
        Write-Host "  - JSON: $($jsonSize) bytes"
        Write-Host "  - TXT: $($txtSize) bytes"
        return $true
    } else {
        Write-Error "❌ 결과 파일 저장 실패: $ItemId"
        return $false
    }
}

# ============================================================================
# Unix 대응 함수 (list_historical_results, cleanup_old_results, generate_result_statistics)
# ============================================================================

# 과거 결과 파일 조회 (Unix list_historical_results 대응)
function Get-HistoricalResults {
    <#
    .SYNOPSIS
        최근 N일 동안의 진단 결과 파일 조회

    .PARAMETER ItemId
        진단 항목 ID (예: "W-01", "WEB-04")

    .PARAMETER Days
        조회할 기간 (일 단위, 기본값: 7일)

    .PARAMETER ScriptDir
        스크립트 디렉토리 경로 (기본값: $SCRIPT_DIR)

    .EXAMPLE
        Get-HistoricalResults -ItemId "W-01" -Days 7
    #>
    param(
        [string]$ItemId,
        [int]$Days = 7,
        [string]$ScriptDir = $SCRIPT_DIR
    )

    $resultsDir = Join-Path $ScriptDir $RESULT_DIR_BASE
    $cutoffDate = (Get-Date).AddDays(-$Days).ToString("yyyyMMdd")

    if (-not (Test-Path $resultsDir)) {
        Write-Host "⚠️  결과 디렉토리 없음: $resultsDir"
        return
    }

    Write-Host "📋 과거 진단 결과 (최근 ${Days}일):"
    Write-Host ""

    # 날짜별 폴더 순회 (최신순)
    $dateDirs = Get-ChildItem -Path $resultsDir -Directory |
                Where-Object { $_.Name -match '^\d{8}$' } |
                Sort-Object Name -Descending

    foreach ($dateDir in $dateDirs) {
        if ($dateDir.Name -ge $cutoffDate) {
            $jsonFiles = Get-ChildItem -Path $dateDir.FullName -Filter "*_${ItemId}_result_*.json" -ErrorAction SilentlyContinue

            if ($jsonFiles.Count -gt 0) {
                Write-Host "📁 $($dateDir.Name):"
                foreach ($file in $jsonFiles) {
                    $timestamp = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Write-Host "   - $($file.Name) ($timestamp)"
                }
                Write-Host ""
            }
        }
    }
}

# 결과 통계 생성 (Unix generate_result_statistics 대응)
function Get-ResultStatistics {
    <#
    .SYNOPSIS
        진단 결과 통계 생성

    .PARAMETER ScriptDir
        스크립트 디렉토리 경로 (기본값: $SCRIPT_DIR)

    .EXAMPLE
        Get-ResultStatistics
    #>
    param(
        [string]$ScriptDir = $SCRIPT_DIR
    )

    $resultsDir = Join-Path $ScriptDir $RESULT_DIR_BASE

    if (-not (Test-Path $resultsDir)) {
        Write-Host "⚠️  결과 디렉토리 없음"
        return
    }

    Write-Host "📊 진단 결과 통계:"
    Write-Host ""

    # 전체 결과 파일 수
    $totalJson = (Get-ChildItem -Path $resultsDir -Filter "*.json" -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    $totalTxt = (Get-ChildItem -Path $resultsDir -Filter "*.txt" -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count

    # 결과별 카운트
    $goodCount = 0
    $vulnerableCount = 0
    $manualCount = 0

    $jsonFiles = Get-ChildItem -Path $resultsDir -Filter "*.json" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $jsonFiles) {
        try {
            $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
            if ($content.final_result -eq "GOOD") { $goodCount++ }
            elseif ($content.final_result -eq "VULNERABLE") { $vulnerableCount++ }
            elseif ($content.final_result -eq "MANUAL") { $manualCount++ }
        } catch {
            # JSON 파싱 실패 시 무시
        }
    }

    Write-Host "총 JSON 결과: $totalJson"
    Write-Host "총 텍스트 결과: $totalTxt"
    Write-Host "양호 (GOOD): $goodCount"
    Write-Host "취약 (VULNERABLE): $vulnerableCount"
    Write-Host "수동진단 (MANUAL): $manualCount"
    Write-Host ""

    return @{
        TotalJson = $totalJson
        TotalTxt = $totalTxt
        GoodCount = $goodCount
        VulnerableCount = $vulnerableCount
        ManualCount = $manualCount
    }
}

# 오래된 결과 정리 (Unix cleanup_old_results 대응)
function Remove-OldResults {
    <#
    .SYNOPSIS
        지정된 일수 이상된 결과 파일 정리

    .PARAMETER KeepDays
        보관할 기간 (일 단위, 기본값: 30일)

    .PARAMETER ScriptDir
        스크립트 디렉토리 경로 (기본값: $SCRIPT_DIR)

    .PARAMETER WhatIf
        실제 삭제 없이 대상만 표시 (기본값: $true)

    .EXAMPLE
        Remove-OldResults -KeepDays 30 -WhatIf $false
    #>
    param(
        [int]$KeepDays = 30,
        [string]$ScriptDir = $SCRIPT_DIR,
        [bool]$WhatIf = $true
    )

    $resultsDir = Join-Path $ScriptDir $RESULT_DIR_BASE

    if (-not (Test-Path $resultsDir)) {
        Write-Host "⚠️  결과 디렉토리 없음: $resultsDir"
        return
    }

    $cutoffDate = (Get-Date).AddDays(-$KeepDays).ToString("yyyyMMdd")

    if ($WhatIf) {
        Write-Host "🔍 ${KeepDays}일 이상된 결과 정리 대상 조회 (WhatIf 모드):"
    } else {
        Write-Host "🧹 ${KeepDays}일 이상된 결과 정리 중..."
    }

    $cleanedCount = 0

    $dateDirs = Get-ChildItem -Path $resultsDir -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -match '^\d{8}$' }

    foreach ($dateDir in $dateDirs) {
        if ($dateDir.Name -lt $cutoffDate) {
            if ($WhatIf) {
                Write-Host "🗑️  삭제 대상: $($dateDir.FullName)"
            } else {
                Write-Host "🗑️  삭제: $($dateDir.FullName)"
                Remove-Item -Path $dateDir.FullName -Recurse -Force
            }
            $cleanedCount++
        }
    }

    if ($cleanedCount -eq 0) {
        Write-Host "✅ 정리할 과거 결과 없음"
    } else {
        if ($WhatIf) {
            Write-Host "✅ $cleanedCount 개 디렉토리 정리 대상 (삭제 미실행)"
            Write-Host "   실제 삭제하려면 -WhatIf:`$false 参数를 사용하세요"
        } else {
            Write-Host "✅ $cleanedCount 개 디렉토리 정리 완료"
        }
    }
}

# ============================================================================
# 함수 내보내기 (모듈로 사용 시 - 주석 처리됨)
# ============================================================================
# Export-ModuleMember는 모듈에서만 사용 가능합니다.
# 이 lib는 일반 스크립트로 사용되므로 Export-ModuleMember를 사용하지 않습니다.

# Export-ModuleMember -Function @(
#     'Get-Hostname',
#     'Test-DiskSpace',
#     'Test-RunallMode',
#     'New-ResultFilePath',
#     'Generate-JsonContent',
#     'Save-JsonResult',
#     'Save-TextResult',
#     'Save-DualResult',
#     'Test-ResultSaved',
#     'Show-DiagnosisStart',
#     'Show-DiagnosisComplete',
#     'Confirm-ResultSaved',
#     'Get-HistoricalResults',
#     'Get-ResultStatistics',
#     'Remove-OldResults'
# )

# ============================================================================
# Run-all 통합 결과 관리 (Unix 형식 - PowerShell)
# ============================================================================

# 전역 변수: run_all 텍스트 파일 경로
$Script:TXT_FILE = $null

# 텍스트 파일 헤더 초기화 (Unix run_all 패턴)
# 사용법: $TXT_FILE = Initialize-RunallTextFile -Category $Category -Platform $Platform -ScriptDir $ScriptDir
function Initialize-RunallTextFile {
    <#
    .SYNOPSIS
        run_all 텍스트 파일 헤더 초기화 (Unix 형식)

    .PARAMETER Category
        카테고리 (예: "DBMS", "Unix")

    .PARAMETER Platform
        플랫폼 (예: "PostgreSQL", "Debian")

    .PARAMETER ScriptDir
        스크립트 디렉토리 경로

    .EXAMPLE
        $TXT_FILE = Initialize-RunallTextFile -Category "DBMS" -Platform "PostgreSQL" -ScriptDir $ScriptDir
    #>
    param(
        [string]$Category,
        [string]$Platform,
        [string]$ScriptDir
    )

    $hostname = Get-Hostname
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dateSuffix = Get-Date -Format "yyyyMMdd"
    $resultDir = Join-Path $ScriptDir "results\$dateSuffix"

    # 결과 디렉토리 생성
    if (-not (Test-Path $resultDir)) {
        New-Item -Path $resultDir -ItemType Directory -Force | Out-Null
    }

    # 텍스트 파일 경로 설정
    $normalizedCategory = $Category -replace ' ', '_'  # 공백을 언더스코어로 변환
    $txtFile = Join-Path $resultDir "${hostname}_${normalizedCategory}_${Platform}_all_results_${timestamp}.txt"

    # 헤더 생성
    $header = @"
==============================================================================
KISA-CIIP-2026 Vulnerability Assessment Scripts
Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
Version: 1.0.0
Last Updated: 2026-01-17
==============================================================================

=================================================================
KISA 취약점 진단 시스템 - 전체 항목 진단 결과
=================================================================

카테고리: ${Category}
플랫폼: ${Platform}
진단 시간: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
호스트네임: ${hostname}

-----------------------------------------------------------------
진단 통계
-----------------------------------------------------------------
"@

    Set-Content -Path $txtFile -Value $header -Encoding UTF8

    return $txtFile
}

# 텍스트 파일에 단일 항목 결과 append (Unix run_all 패턴)
# 사용법: Append-RunallTextResult -JsonObj $jsonObj -TxtFile $txtFile
function Append-RunallTextResult {
    <#
    .SYNOPSIS
        JSON 결과를 텍스트 파일에 추가 (Unix 형식)

    .PARAMETER JsonObj
        JSON 객체 문자열

    .PARAMETER TxtFile
        텍스트 파일 경로

    .EXAMPLE
        Append-RunallTextResult -JsonObj $jsonOutput -TxtFile $TXT_FILE
    #>
    param(
        [string]$JsonObj,
        [string]$TxtFile
    )

    try {
        $json = $JsonObj | ConvertFrom-Json

        $itemId = $json.item_id
        $itemName = $json.item_name

        # inspection.summary 추출
        $summary = if ($json.inspection) { $json.inspection.summary } else { $json.summary }

        $command = $json.command
        $commandResult = $json.command_result
        # \r\n 이스케이프 문자를 실제 줄바꿈으로 변환
        $commandResult = $commandResult -replace '\\r\\n', "`r`n" -replace '\\n', "`n" -replace '\\r', "`r"
        $finalResult = $json.final_result

        # guideline 추출
        $guideline = $json.guideline
        $purpose = if ($guideline) { $guideline.purpose } else { "" }
        $threat = if ($guideline) { $guideline.security_threat } else { "" }
        $criteriaGood = if ($guideline) { $guideline.judgment_criteria_good } else { "" }
        $criteriaBad = if ($guideline) { $guideline.judgment_criteria_bad } else { "" }
        $remediation = if ($guideline) { $guideline.remediation } else { "" }

        # TXT 형식으로 append
        $content = @"

============================================================
[${itemId}]${itemName}
============================================================
[${itemId}-START]

${summary}

[현황]
1) 진단 확인
command: ${command}
command_result:
${commandResult}

[${itemId}-END]

[${itemId}]Result : ${finalResult}

[참고]
진단 목적: ${purpose}
보안 위협: ${threat}
양호 기준: ${criteriaGood}
취약 기준: ${criteriaBad}
조치 방법: ${remediation}

============================================================
"@

        Add-Content -Path $TxtFile -Value $content -Encoding UTF8
    }
    catch {
        Write-Warning "JSON 파싱 실패: $_"
    }
}

# 통합 결과 파일 생성 (최종 JSON + 텍스트 푸터)
# 사용법: New-RunallAggregatedResults -Category $Category -Platform $Platform -ScriptDir $ScriptDir -TotalItems $totalItems -ResultsJson $resultsJsonArray
function New-RunallAggregatedResults {
    <#
    .SYNOPSIS
        run_all 통합 결과 생성 (JSON + 텍스트 푸터)

    .PARAMETER Category
        카테고리

    .PARAMETER Platform
        플랫폼

    .PARAMETER ScriptDir
        스크립트 디렉토리

    .PARAMETER TotalItems
        총 항목 수

    .PARAMETER ResultsJson
        결과 JSON 배열 (passed/failed는 JSON에서 추출)

    .EXAMPLE
        New-RunallAggregatedResults -Category "DBMS" -Platform "PostgreSQL" -ScriptDir $ScriptDir -TotalItems 26 -ResultsJson $results
    #>
    param(
        [string]$Category,
        [string]$Platform,
        [string]$ScriptDir,
        [int]$TotalItems,
        [string[]]$ResultsJson
    )

    $hostname = Get-Hostname
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dateSuffix = Get-Date -Format "yyyyMMdd"
    $resultDir = Join-Path $ScriptDir "results\$dateSuffix"

    # 결과 디렉토리 생성
    if (-not (Test-Path $resultDir)) {
        New-Item -Path $resultDir -ItemType Directory -Force | Out-Null
    }

    # ResultsJson에서 passed/failed 추출
    $goodItemsArray = @()       # 양호 (GOOD)
    $vulnItemsArray = @()       # 취약 (VULNERABLE)
    $manualItemsArray = @()      # 수동진단 (MANUAL)
    $errorItemsArray = @()       # 진단 실패/N/A
    $resultsJsonArray = @()

    foreach ($jsonObj in $ResultsJson) {
        try {
            $parsed = $jsonObj | ConvertFrom-Json
            $resultsJsonArray += $parsed

            # final_result에 따라 분류
            switch ($parsed.final_result) {
                "GOOD" {
                    $goodItemsArray += $parsed.item_id
                }
                "VULNERABLE" {
                    $vulnItemsArray += $parsed.item_id
                }
                "MANUAL" {
                    $manualItemsArray += $parsed.item_id
                }
                default {
                    $errorItemsArray += $parsed.item_id
                }
            }
        }
        catch {
            Write-Warning "JSON 파싱 실패: $_"
        }
    }

    $goodCount = $goodItemsArray.Count
    $vulnCount = $vulnItemsArray.Count
    $manualCount = $manualItemsArray.Count
    $errorCount = $errorItemsArray.Count
    $totalCount = $goodCount + $vulnCount + $manualCount + $errorCount

    # 통계를 텍스트 파일에 append
    if ($Script:TXT_FILE -and (Test-Path $Script:TXT_FILE)) {
        $goodRate = if ($TotalItems -gt 0) { "{0:N1}" -f (($goodCount * 100.0) / $TotalItems) } else { "0.0" }

        $stats = @"

총 항목: ${TotalItems}
양호: ${goodCount}
취약: ${vulnCount}
N/A: ${errorCount}
수동: ${manualCount}
양호율: ${goodRate}%

-----------------------------------------------------------------
양호 항목 (${goodCount}개)
-----------------------------------------------------------------
$($goodItemsArray -join "`n")

-----------------------------------------------------------------
취약 항목 (${vulnCount}개)
-----------------------------------------------------------------
$($vulnItemsArray -join "`n")

-----------------------------------------------------------------
수동 진단 항목 (${manualCount}개)
-----------------------------------------------------------------
$($manualItemsArray -join "`n")

-----------------------------------------------------------------
진단 실패/N/A 항목 (${errorCount}개)
-----------------------------------------------------------------
$($errorItemsArray -join "`n")

"@

        Add-Content -Path $Script:TXT_FILE -Value $stats -Encoding UTF8

        # 텍스트 파일에 푸터 추가
        $footer = @"

=================================================================
진단 시간: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
=================================================================
"@

        Add-Content -Path $Script:TXT_FILE -Value $footer -Encoding UTF8
        Write-Host "📄 통합 텍스트 결과 완료: $Script:TXT_FILE"
    }

    # JSON 통합 결과 생성
    $normalizedCategory = $Category -replace ' ', '_'  # 공백을 언더스코어로 변환
    $jsonFile = Join-Path $resultDir "${hostname}_${normalizedCategory}_${Platform}_all_results_${timestamp}.json"

    $jsonContent = @{
        category = $Category
        platform = $Platform
        total_items = $TotalItems
        good_items = $goodCount
        vulnerable_items = $vulnCount
        manual_items = $manualCount
        error_items = $errorCount
        timestamp = (Get-Date).ToString("o")
        hostname = $hostname
        items = $resultsJsonArray
    } | ConvertTo-Json -Depth 10

    Set-Content -Path $jsonFile -Value $jsonContent -Encoding UTF8
    Write-Host "📊 통합 JSON 결과 저장: $jsonFile"
}
