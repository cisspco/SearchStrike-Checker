# SearchStrike IOC Snapshot — 2026-11-06 UTC

## 수집 상태
- 페치 성공: microsoft.com (SearchStrike 검색 결과 0건), cloud.google.com ("DPRK adopts EtherHiding" — 무관한 별개 캠페인 UNC5342/JADESNOW/INVISIBLEFERRET로 재확인)
- 페치 차단: malwarebytes.com, cybersecuritynews.com, securityarsenal.com, safedep.io, dev.to, boho.or.kr (전부 DNS 조회 실패/ENOTFOUND)
- 한국 소스 접근 가능 여부: boho.or.kr 1곳 시도(페치 cap 소진으로 krcert.or.kr/asec.ahnlab.com/igloo.co.kr/sk-shieldus.com은 이번에 시도하지 않음), DNS 조회 자체가 실패해 접근 불가
- seed: 27 (C2 10 + RPC 6 + 해시 11) / 검증: 0 / 미검증: 0 / 검토 필요: 4

## 캠페인 개요
SearchStrike(= 2차 보도 기준 EtherRAT으로 통칭)는 Tftpd64, Postman, WinDbg, PsExec, USMT, IntuneWinAppUtil, BgInfo, RDCMan 등 IT 관리자/개발자가 흔히 쓰는 정상 유틸리티를 위장한 트로이목마 설치파일로 시작되며, `%LOCALAPPDATA%` 하위의 무작위 6자리 디렉터리에 node.exe를 드롭하고 HKCU/HKLM Run 키 및 16진수 이름의 레지스트리 서브키로 지속성을 확보한다. `msiexec → cmd → node.exe`, `explorer → node.exe` 프로세스 체인과 `.xml/.bak/.cfg/.bin/.ini` 형태의 고엔트로피 설정 페이로드가 특징이며, C2는 공개 이더리움 RPC 엔드포인트를 통해 블록체인에 숨겨진 주소를 조회하는 "EtherHiding" 기법을 사용한다. 이번 실행에서도 변동 없음: 전날(2026-11-05) 대비 동일한 지표 구성을 유지.

## 공격자 C2 도메인 (차단 대상) (10)
- aurineuroth[.]com — seed
- euclidrent[.]com — seed
- hayesmed[.]com — seed
- jariosos[.]com — seed
- justtalken[.]com — seed
- mebeliotmasiv[.]com — seed
- o-parana[.]com — seed
- palshona[.]com — seed
- regancontrols[.]com — seed
- salinasrent[.]com — seed

## 악용된 정상 인프라 — 블록체인 RPC (차단 금지, 헌팅 신호로만 사용) (6)
- 1rpc[.]io — 1RPC (public Ethereum RPC)
- eth.llamarpc[.]com — LlamaNodes
- mainnet.blockpi.network — BlockPI
- rpc.blastapi[.]io — Blast API
- rpc.drpc[.]io — dRPC
- rpc.flashbots[.]net — Flashbots Protect RPC

## 검토 필요 (4)
- hereusers.allsettled[.]net — 도메인 형태부터 RPC 인프라로 보이지 않으며 어떤 이더리움 RPC 제공업체와도 일치하지 않음
- rpc.lokichain[.]io — "Lokichain"은 알려진 주요 이더리움 RPC/체인 제공업체가 아님, 검색으로 확인되는 서비스 없음
- rpc.mevblock[.]io — 실제 MEV Blocker 서비스 도메인은 mevblocker.io / rpc.mevblocker.io이며, 스크립트에는 rpc.mevblock.io로 기재됨(철자 불일치) — 정상 제공업체 사칭 가능성, 알려진 RPC 목록과 일치하지 않아 검토 필요. 이번 실행에서도 malwarebytes.com 원문 페치가 차단되어 정확한 호스트명을 여전히 검증하지 못했습니다.
- rpc.payload[.]de — 알려진 공개 이더리움 RPC 제공업체(Alchemy, Infura, dRPC, BlockPI, LlamaRPC, Blast API, Flashbots 등) 목록에서 확인되지 않음

## 파일 해시 (11)
### SHA-256
- 3abe9aa1b6a9f2f779f875773e077e0129e770e98fcbee60c0137f656f4fe82e — Tftpd64, 2026-03-09 — seed
- 3ddfcc93aefab5a671edb4c643a810b7a2a7b35629c27f3f68849cf390a26025 — Postman, 2026-02-17 — seed
- ab79d9ef9fddb880bbfc5e2587566884da9510988005f2737493cfc25437b8ba — WinDbg, 2026-03-10 — seed
- c03e9aade86079a2d4007b58e3b419dfe821bf64366fd3a9c3d04dd63b5e7779 — PsExec, 2026-03-10 — seed
- c3910810dc87e1a5993d4e4234fd3f94fa7ecf66735fd0396be73b2379aafabd — Tftpd64, 2026-02-23 — seed
- d6acbd0cf0c99c76c3f09f68792eabb843fd539ae42573ecdfeda63fa695dcd2 — Tftpd64, 2026-02-17 — seed
- e3df11e259647e00de5f6119fce20c07f551b4bb5b3c4da3fb07956c0c3d69ff — BgInfo, 2026-03-10 — seed
- eb2a4c6e88adc5b56dcb6a39bf749564d5b72fbb5ba2dc3c603ba183a99bccb4 — USMT, 2026-03-10 — seed
- ece54f2a68530222604014dd5b23520bb1729efe7ea15a822c1ea16556ed8257 — Tftpd64, 2026-03-10 — seed
- f88532089976d65463869a1ab5e8f050d8f3ee49501a5fa7883f80ac86b20a84 — RDCMan, 2026-03-10 — seed
- fc9da1e9c12930f1c324b4dee5918033a644d090a96f69ff3669711d4219158b — IntuneWinAppUtil, 2026-03-10 — seed

## 호스트 IOC · 행위
- `%LOCALAPPDATA%\<임의 6자리>\node.exe` — 드롭된 Node.js 런타임
- HKCU/HKLM `...\Run` 키, 16진수 이름의 레지스트리 서브키 — 지속성
- 프로세스 체인: `msiexec → cmd → node.exe`, `explorer → node.exe`
- AppData/Temp 내 `.xml`, `.bak`, `.cfg`, `.bin`, `.ini` 고엔트로피 설정 페이로드
- 위장 대상 정상 유틸리티: Tftpd64, Postman, WinDbg, PsExec, USMT, IntuneWinAppUtil, BgInfo, RDCMan

## 이번 실행 변경사항
- 신규 C2: 없음
- 신규 해시: 없음
- 승격(→검증): 없음
- 분류 변경: 없음
- 신규 보고서: 없음 (WebSearch 5건에서 신규 2차 보도 후보는 없었고, 기존에 이미 특정된 EtherRAT 2차 보도(dev.to, cybersecuritynews.com, malwarebytes.com, securityarsenal.com, safedep.io)만 재확인되었습니다. 추가로 cyberwarzone.com "SleepyDuck Malware Redefines C2 Resilience with Ethereum Blockchain"을 신규 후보로 발견했으나, SleepyDuck은 자체 백업 C2 주소/폴링 설정을 이더리움 컨트랙트에 보관하는 별개의 블록체인 C2 RAT 패밀리로 보여(SearchStrike/EtherRAT와 무관) 미채택했습니다. 페치 8건 중 microsoft.com과 cloud.google.com만 성공했고, 나머지 6건(malwarebytes.com, cybersecuritynews.com, securityarsenal.com, safedep.io, dev.to, boho.or.kr)은 전부 DNS 조회 실패(ENOTFOUND)로 차단되어 본문을 확인하지 못했습니다. cloud.google.com "DPRK adopts EtherHiding"은 UNC5342/JADESNOW/INVISIBLEFERRET 캠페인 본문을 상세히 재확인했으나 SearchStrike 특유의 위장 도구(Tftpd64/Postman/WinDbg 등)나 RPC 엔드포인트 목록은 포함하지 않아 여전히 무관합니다. `rpc.mevblock.io` 및 `mainnet.gateway.tenderly.co` 감시 항목 모두 malwarebytes.com 페치 차단으로 여전히 미확정 상태입니다. 페치 cap 소진으로 한국 소스는 boho.or.kr 1곳만 시도했으며 이번에도 DNS 조회 자체가 실패해 접근 불가했습니다.)

## 스크립트 반영 필요 (수작업)
없음 (SCRIPT-SYNC.md 참조 — 현재 반영 대기 항목 없음)

## 차단 운영 포맷 (복붙용)

### Domain blocklist (un-defanged, one per line — attacker C2 only)
```
aurineuroth.com
euclidrent.com
hayesmed.com
jariosos.com
justtalken.com
mebeliotmasiv.com
o-parana.com
palshona.com
regancontrols.com
salinasrent.com
```

## 출처
- [SearchStrike-Checker.ps1](https://github.com/cisspco/SearchStrike-Checker) — seed(.ps1)
- [Microsoft Security Blog search — "SearchStrike"](https://www.microsoft.com/en-us/security/blog/?s=SearchStrike) — 2026-11-06 — fetched (0 results)
- [Google Cloud Threat Intelligence — "DPRK adopts EtherHiding"](https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding) — 2025-10-16 — fetched (무관한 별개 캠페인 UNC5342/JADESNOW/INVISIBLEFERRET로 확인)
- malwarebytes.com — "Inside a malicious infrastructure delivering EtherRAT, phishing pages, and malicious software" (?p=424132) — blocked (ENOTFOUND)
- cybersecuritynews.com — "Hackers Use EtherRAT and EtherHiding" — blocked (ENOTFOUND)
- securityarsenal.com — "GlassWorm, EtherRAT and RebexRAT: Blockchain C2 and Multi-Stage Supply Chain Attacks" — blocked (ENOTFOUND)
- safedep.io — "EtherHiding: Blockchain-Based C2 Bootstrapping" — blocked (ENOTFOUND)
- dev.to — "EtherRAT: How North Korean Hackers Weaponized Ethereum Smart Contracts" — blocked (ENOTFOUND)
- boho.or.kr — DNS resolution failed (blocked)
- cyberwarzone.com — "SleepyDuck Malware Redefines C2 Resilience with Ethereum Blockchain" — not fetched (별개 패밀리로 판단, WebSearch 스니펫만 근거)
