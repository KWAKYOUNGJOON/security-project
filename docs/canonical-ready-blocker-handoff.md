# Canonical READY Blocked Handoff

## 현재 상태 요약

현재 canonical READY 상태는 `BLOCKED`다.

canonical real input target 4개는 아래 경로다.

- `data\inputs\real\burp\burp-findings.json`
- `data\inputs\real\nuclei\nuclei-findings.json`
- `data\inputs\real\httpx\httpx-hosts.json`
- `data\inputs\real\manual\manual-findings.json`

현재 판정은 아래와 같다.

- `burp-findings.json` = `REAL SOURCE EXISTS BUT MAPPING AMBIGUOUS`
- `nuclei-findings.json` = `NO REAL SOURCE FOUND`
- `httpx-hosts.json` = `NO REAL SOURCE FOUND`
- `manual-findings.json` = `NO REAL SOURCE FOUND`

real input 4개가 모두 준비되기 전까지 `smoke` 와 `compare-runs` 는 실행 금지다.

## blocker 상세

BLOCKED 사유는 canonical real input 4개가 모두 준비되지 않았기 때문이다.

Burp는 실제 artifact 후보가 있으나 target 의미와의 매핑이 확정되지 않았다.

Nuclei, httpx, manual은 실제 raw original이 아직 확보되지 않았다.

placeholder, mock, synthetic, sample, fixture, test-only 산출물은 금지다.

## Burp ambiguity 설명

Burp 실제 후보 artifact는 아래 파일이다.

- `d:\security-project\intake\web\hexstrike-ai\run-juice-001\raw\hexstrike-result.json`

확정 사실은 아래와 같다.

- manifest 기준 `contains_real_scan_data=true`
- tool=`burpsuite_alternative_scan`
- `summary-only aggregate`

해석 충돌은 아래 두 축에서 발생한다.

- machine contract 관점: canonical code는 target 파일의 존재 여부와 SHA256만 사용하고 내부 parser/loader는 없다
- 운영 의미 관점: 문서와 파일명은 `burp-findings.json` 을 Burp findings 의미로 전제한다

따라서 Burp는 실제 source가 존재하지만, maintainer 결정 전까지는 무단 매핑하지 않고 보류한다.

## missing artifact 상세

아직 실제 raw original이 확보되지 않은 항목은 아래와 같다.

- `data\inputs\real\nuclei\nuclei-findings.json`
- `data\inputs\real\httpx\httpx-hosts.json`
- `data\inputs\real\manual\manual-findings.json`

이 3개는 실제 raw original 확보 전까지 blocker 해소가 불가능하다.

## maintainer 문의 문안

`d:\security-project\intake\web\hexstrike-ai\run-juice-001\raw\hexstrike-result.json` 은 manifest 기준 `contains_real_scan_data=true` 인 real live artifact이고 tool은 `burpsuite_alternative_scan`입니다. 현재 canonical code는 `data/inputs/real/burp/burp-findings.json` 의 존재 여부와 SHA256만 사용하며 내부 parser/loader는 없습니다. 다만 문서와 파일명 의미상으로는 Burp findings 의미 보존 이슈가 있고, 이 artifact는 `summary-only aggregate`라 무단 매핑을 보류 중입니다. READY blocker 해소를 위해 이 파일을 `burp-findings.json` 로 `허용 / 불허 / 조건부 허용` 중 하나로 답변 부탁드립니다.

## upstream 요청 문안

READY blocker 해소를 위해 canonical real input용 실제 raw original 3종이 필요합니다: `nuclei-findings`, `httpx-hosts`, `manual-findings`. 각 항목별로 원본 파일 경로 또는 원본 파일 자체, 생성 도구명과 버전, 생성 명령 또는 export 절차, 생성 시각, 레코드 수, 민감정보 마스킹 여부를 함께 전달해 주세요. placeholder, sample, fixture, synthetic, test-only 산출물은 사용할 수 없고 실제 raw original만 허용됩니다.

## 지금 하면 안 되는 작업

- target 4개 경로에 임의 파일 생성
- placeholder 또는 더미 JSON 배치
- Burp artifact 무단 복사 또는 정규화
- `smoke` 실행
- `compare-runs` 실행
- 테스트 재실행
- 스캔 재실행
- 추가 탐색

## 외부 입력 수신 후 재개 조건

외부 입력이 들어오기 전까지는 상태를 그대로 유지한다.

재개를 위해 필요한 입력은 아래와 같다.

- maintainer의 Burp 허용/불허/조건부 허용 응답
- Nuclei 실제 raw original
- httpx 실제 raw original
- manual 실제 raw original

TODO

- maintainer 응답 내용을 기준으로 Burp target 배치 가능 여부만 다시 판정한다
- nuclei/httpx/manual 실제 raw original 확보 여부만 다시 확인한다
- target 4개 경로 배치 가능 여부를 다시 판정한다
- real input 4개가 모두 준비된 경우에만 canonical 재검증 단계로 이동한다

## 다음 단일 액션

maintainer에게 Burp 매핑 허용 여부를 먼저 확인한다.

## 재개 조건 체크리스트

- [ ] maintainer Burp 허용/불허/조건부 허용 응답 확보
- [ ] nuclei raw original 확보
- [ ] httpx raw original 확보
- [ ] manual raw original 확보
- [ ] target 4개 경로 배치 가능 여부 확인
