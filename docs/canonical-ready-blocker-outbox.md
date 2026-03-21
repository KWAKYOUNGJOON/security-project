# Canonical READY Blocker Outbox

## 목적

이 문서는 현재 canonical READY blocker 상태에서 외부 발송에 바로 사용할 고정 문안을 정리한 outbox 패키지다.

기준 상태는 `canonical READY = BLOCKED` 이며, 외부 입력이 들어오기 전까지 내부 실행은 멈춘 상태로 유지한다.

참조 handoff 문서:

- `d:\security-project\docs\canonical-ready-blocker-handoff.md`

## 현재 상태 한눈에 보기

- canonical READY = `BLOCKED`
- Burp = `real source exists but mapping ambiguous`
- Nuclei/httpx/manual = `no real source found`
- real input 4개 준비 전 `smoke` / `compare-runs` 실행 금지

## maintainer 발송 문안

```text
d:\security-project\intake\web\hexstrike-ai\run-juice-001\raw\hexstrike-result.json 은 manifest 기준 contains_real_scan_data=true 인 real live artifact이고 tool은 burpsuite_alternative_scan입니다. 현재 canonical code는 data/inputs/real/burp/burp-findings.json 의 존재 여부와 SHA256만 사용하며 내부 parser/loader는 없습니다. 다만 문서와 파일명 의미상으로는 Burp findings 의미 보존 이슈가 있고, 이 artifact는 summary-only aggregate라 무단 매핑을 보류 중입니다. READY blocker 해소를 위해 이 파일을 burp-findings.json 로 허용 / 불허 / 조건부 허용 중 하나로 답변 부탁드립니다.
```

## upstream 발송 문안

```text
READY blocker 해소를 위해 canonical real input용 실제 raw original 3종이 필요합니다: nuclei-findings, httpx-hosts, manual-findings. 각 항목별로 원본 파일 경로 또는 원본 파일 자체, 생성 도구명과 버전, 생성 명령 또는 export 절차, 생성 시각, 레코드 수, 민감정보 마스킹 여부를 함께 전달해 주세요. placeholder, sample, fixture, synthetic, test-only 산출물은 사용할 수 없고 실제 raw original만 허용됩니다.
```

## 회신 기록 템플릿

```text
수신자:
발송 채널:
발송 시각:
회신 시각:
회신 요지:
결정/판정:
다음 액션:
```

## 회신별 후속 판단 기준

- maintainer가 Burp를 허용하면 Burp blocker는 조건부 해소 가능
- maintainer가 불허하면 Burp raw original 추가 확보 필요
- maintainer가 조건부 허용하면 조건 문구를 그대로 보존해야 함
- nuclei/httpx/manual는 실제 raw original 확보 전까지 계속 blocker

## 외부 입력 전 금지 작업

- 임의 target 파일 생성
- 무단 매핑
- `smoke` 실행
- `compare-runs` 실행
- 테스트 재실행
- 스캔 재실행
- 추가 탐색

## 재개 조건

- maintainer Burp 응답 확보
- nuclei raw original 확보
- httpx raw original 확보
- manual raw original 확보
- target 4개 경로 배치 가능 여부 확인
