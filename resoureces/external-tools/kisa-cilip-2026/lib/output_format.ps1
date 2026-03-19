# KISA 취약점 진단 시스템 - 출력 형식 관리자 (PowerShell)
# Encoding: UTF-8, CRLF
# Purpose: TXT 결과 파일 형식 중앙 관리
# Platform: Windows Server, IIS, PC, DBMS

#Requires -Version 5.1

# ============================================================================
# TXT 결과 내용 생성 (개별 실행 모드용)
# ============================================================================

function New-TextResultContent {
    <#
    .SYNOPSIS
        TXT 결과 내용 생성 (개별 실행 모드용)

    .DESCRIPTION
        Appendix C 형식에 맞는 TXT 결과 내용을 생성합니다.
        모든 PowerShell 진단 스크립트가 동일한 형식을 사용하도록 보장합니다.

    .PARAMETER ItemId
        진단 항목 ID (예: "W-01", "WEB-04")

    .PARAMETER ItemName
        진단 항목 이름

    .PARAMETER InspectionSummary
        진단 요약

    .PARAMETER CommandResult
        명령 실행 결과

    .PARAMETER CommandExecuted
        실행한 명령

    .PARAMETER FinalResult
        최종 결과 (GOOD/VULNERABLE/MANUAL/N/A)

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
        String[] - TXT 라인 배열

    .EXAMPLE
        $txtLines = New-TextResultContent -ItemId "W-01" -ItemName "Administrator계정이름변경" ...
    #>
    param(
        [string]$ItemId,
        [string]$ItemName,
        [string]$InspectionSummary,
        [string]$CommandResult,
        [string]$CommandExecuted,
        [string]$FinalResult,
        [string]$GuidelinePurpose,
        [string]$GuidelineThreat,
        [string]$GuidelineCriteriaGood,
        [string]$GuidelineCriteriaBad,
        [string]$GuidelineRemediation
    )

    $txtLines = @()
    $txtLines += '============================================================'
    $txtLines += "[$ItemId] $ItemName"
    $txtLines += '============================================================'
    $txtLines += "[$ItemId-START]"
    $txtLines += ''
    $txtLines += $InspectionSummary
    $txtLines += ''
    $txtLines += '[현황]'
    $txtLines += '1) 진단 명령 실행'
    $txtLines += "command: $CommandExecuted"
    $txtLines += 'command_result:'
    $txtLines += $CommandResult
    $txtLines += ''
    $txtLines += "[$ItemId-END]"
    $txtLines += ''
    $txtLines += "[$ItemId]Result : $FinalResult"
    $txtLines += ''
    $txtLines += '[참고]'
    $txtLines += "진단 목적: $GuidelinePurpose"
    $txtLines += "보안 위협: $GuidelineThreat"
    $txtLines += "양호 기준: $GuidelineCriteriaGood"
    $txtLines += "취약 기준: $GuidelineCriteriaBad"
    $txtLines += "조치 방법: $GuidelineRemediation"
    $txtLines += ''
    $txtLines += '============================================================'

    return $txtLines
}

# ============================================================================
# TXT 결과 내용 생성 (Run-all 모드용)
# ============================================================================

function New-RunAllTextResultContent {
    <#
    .SYNOPSIS
        TXT 결과 내용 생성 (Run-all 모드용)

    .DESCRIPTION
        Run-all 모드에서 통합 TXT 파일에 추가할 내용을 생성합니다.
        개별 실행 모드와 동일한 형식을 사용합니다.

    .PARAMETER ItemId
        진단 항목 ID

    .PARAMETER ItemName
        진단 항목 이름

    .PARAMETER InspectionSummary
        진단 요약

    .PARAMETER CommandResult
        명령 실행 결과

    .PARAMETER CommandExecuted
        실행한 명령

    .PARAMETER FinalResult
        최종 결과

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
        String[] - TXT 라인 배열

    .EXAMPLE
        $txtLines = New-RunAllTextResultContent -ItemId "W-01" ...
    #>
    param(
        [string]$ItemId,
        [string]$ItemName,
        [string]$InspectionSummary,
        [string]$CommandResult,
        [string]$CommandExecuted,
        [string]$FinalResult,
        [string]$GuidelinePurpose,
        [string]$GuidelineThreat,
        [string]$GuidelineCriteriaGood,
        [string]$GuidelineCriteriaBad,
        [string]$GuidelineRemediation
    )

    # Run-all 모드도 개별 실행 모드와 동일한 형식 사용 (Unix와 동일)
    return (New-TextResultContent @PSBoundParameters)
}

# ============================================================================
# 함수 내보내기 (모듈로 사용 시 - 주석 처리됨)
# ============================================================================
# Export-ModuleMember는 모듈에서만 사용 가능합니다.
# 이 lib는 일반 스크립트로 사용되므로 Export-ModuleMember를 사용하지 않습니다.

# Export-ModuleMember -Function @(
#     'New-TextResultContent',
#     'New-RunAllTextResultContent'
# )
