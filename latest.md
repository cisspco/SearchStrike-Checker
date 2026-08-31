# SearchStrike IOC Snapshot — 2026-08-31 UTC

## 수집 상태
- 페치 성공: [Threat actors misuse Node.js to deliver malware and other malicious payloads](https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/) — 단, 내용은 SearchStrike/EtherRAT 캠페인과 무관 (다른 C2 인프라: trycloudflare.com 터널)
- 페치 차단: cybersecuritynews.com, cyberone.kr, esentire.com, sysdig.com, boho.or.kr, scworld.com, asec.ahnlab.com
- 한국 소스 접근 가능 여부: boho.or.kr → 차단, asec.ahnlab.com → 차단. krcert.or.kr / igloo.co.kr / sk-shieldus.com는 이번 실행에서 페치 예산(8건) 소진으로 시도하지 못함 — 다음 실행에서 우선 시도 필요
- seed: 30 / 검증: 0 / 미검증: 0 / 검토 필요: 4

## 캠페인 개요
SearchStrike는 KISA가 명명한 헌팅 가이드이며, 공개 위협 인텔리전스 업계에서는 동일 캠페인이 **EtherRAT**로 광범위하게 추적되고 있음(WebSearch 스니펫 기준, 미검증). GitHub에 Tftpd64·Postman·WinDbg·PsExec·USMT·IntuneWinAppUtil·BgInfo·RDCMan 등 정상 관리 도구를 가장한 트로이목마화 MSI 설치파일을 올리고 SEO로 검색 상위 노출시켜 유포. 실행 시 %LOCALAPPDATA%\<랜덤 6자>\에 node.exe를 심고 Run 키/hex 서브키로 지속성을 확보하며, msiexec→cmd→node.exe 또는 explorer→node.exe 프로세스 체인으로 재실행됨. C2는 이더리움 스마트 컨트랙트에 저장된 주소를 공개 RPC 엔드포인트로 조회해 얻는 "EtherHiding" 방식(WebSearch 스니펫 기준, 미검증) — jariosos.com, hayesmed.com 등 seed 도메인이 EtherRAT 인프라로 언급됨. 참고(SearchStrike IOC 아님): 2025-04 Microsoft 리포트의 별개 Node.js 악성코드 캠페인(trycloudflare.com 터널 사용), CVE-2025-55182(React2Shell) 취약점을 악용하는 다른 EtherRAT 변종(ASEC, 페치 차단됨).

## 공격자 C2 도메인 (차단 대상) (10)
- jariosos[.]com — EtherRAT 인프라로 지목(WebSearch 스니펫, securityarsenal.com 인용: 2025-12-17 신규 등록) — seed ⚠️ (미검증)
- hayesmed[.]com — EtherRAT 인프라로 지목(WebSearch 스니펫) — seed ⚠️ (미검증)
- regancontrols[.]com — .ps1 하드코딩 목록 — seed
- salinasrent[.]com — .ps1 하드코딩 목록 — seed
- justtalken[.]com — .ps1 하드코딩 목록 — seed
- mebeliotmasiv[.]com — .ps1 하드코딩 목록 — seed
- euclidrent[.]com — .ps1 하드코딩 목록 — seed
- o-parana[.]com — .ps1 하드코딩 목록 — seed
- palshona[.]com — .ps1 하드코딩 목록 — seed
- aurineuroth[.]com — .ps1 하드코딩 목록 — seed

## 악용된 정상 인프라 — 블록체인 RPC (차단 금지, 헌팅 신호로만 사용) (5)
- eth.llamarpc[.]com — LlamaRPC (공개 이더리움 RPC 제공업체)
- mainnet.blockpi[.]network — BlockPI Network (공개 이더리움 RPC 제공업체)
- rpc.blastapi[.]io — Blast API / Ankr (공개 이더리움 RPC 제공업체)
- rpc.drpc[.]io — dRPC (공개 이더리움 RPC 제공업체)
- rpc.flashbots[.]net — Flashbots Protect RPC (공개 이더리움 RPC 제공업체)

## 검토 필요 (4)
- rpc.mevblock[.]io — 실제 MEV Blocker 서비스 도메인은 mevblocker[.]io / rpc.mevblocker[.]io이며 스크립트에는 철자가 다른 rpc.mevblock[.]io로 기재되어 있음. 정상 제공업체 사칭 호스트일 가능성이 있어 신뢰 그룹에서 이동함
- rpc.payload[.]de — 알려진 공개 이더리움 RPC 제공업체(Alchemy, Infura, dRPC, BlockPI, LlamaRPC, Blast API, Flashbots 등) 목록에서 확인되지 않음
- hereusers.allsettled[.]net — 도메인 형태 자체가 RPC 인프라로 보이지 않으며 어떤 이더리움 RPC 제공업체와도 일치하지 않음
- rpc.lokichain[.]io — "Lokichain"은 알려진 주요 이더리움 RPC/체인 제공업체가 아니며 검색으로 확인되는 서비스가 없음

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
- %LOCALAPPDATA%\<랜덤 6자 알파뉴메릭>\...\node.exe — 악성 node.exe 드롭 경로
- HKCU/HKLM \Software\Microsoft\Windows\CurrentVersion\Run — node.exe 실행 항목 지속성
- HKCU\Software\<hex 랜덤 서브키> — 값이 .cfg/.ini/.bin/.bak 또는 LOCALAPPDATA 경로인 경우 의심
- 프로세스 체인: msiexec.exe → cmd.exe → node.exe (초기 감염), explorer.exe → node.exe (재부팅 후 Run 키 실행)
- %LOCALAPPDATA%, %APPDATA%, %TEMP% 내 고엔트로피(Shannon ≥7.2) .xml/.bak/.cfg/.bin/.ini 페이로드
- %LOCALAPPDATA%\Temp 내 랜덤명(4~16자 영숫자) .cmd 스크립트 — MSI 설치 잔존물

## 이번 실행 변경사항
- 신규 C2: 없음 (최초 실행 — .ps1에서 10건 시드 추출)
- 신규 해시: 없음 (최초 실행 — .ps1에서 11건 시드 추출)
- 승격(→검증): 없음 (성공 페치된 리포트 없음)
- 분류 변경: rpc.mevblock.io, rpc.payload.de, hereusers.allsettled.net, rpc.lokichain.io — RPC(신뢰) → 검토 필요 (알려진 공개 이더리움 RPC 제공업체와 불일치, 근거는 위 "검토 필요" 섹션 참고)
- 신규 보고서: 없음 (공개 보고서 다수 존재 확인되었으나 페치 성공한 것은 SearchStrike와 무관한 1건뿐)

## 스크립트 반영 필요 (수작업)
없음 — 이번 실행에서 확인된 모든 지표는 이미 .ps1에 포함된 시드 데이터이며 새로 추가된 지표 없음.

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
- [SearchStrike-Checker.ps1 하드코딩 IOC 배열](SearchStrike-Checker.ps1) — seed(.ps1)
- [Threat actors misuse Node.js to deliver malware and other malicious payloads](https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/) — 2025-04-15 — fetched (SearchStrike와 무관, 참고용)
- New EtherRAT Variant Uses Trojanized Tftpd64 Installer (cybersecuritynews.com) — blocked
- 개발자 대상 유틸리티 도구로 위장한 악성코드 유포 주의 권고 (cyberone.kr) — blocked
- EtherRAT & SYS_INFO Module: C2 on Ethereum (EtherHiding) (esentire.com) — blocked
- EtherRAT: DPRK uses novel Ethereum implant in React2Shell attacks (sysdig.com) — blocked
- More sophisticated EtherRAT malware variant delivered via trojanized installer (scworld.com) — blocked
- Distribution of EtherRAT Malware Exploiting React2Shell Vulnerability CVE-2025-55182 (asec.ahnlab.com) — blocked
- KISA 보호나라 공지 (boho.or.kr) — blocked
