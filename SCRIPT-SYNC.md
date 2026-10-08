# SCRIPT-SYNC — SearchStrike-Checker.ps1 반영 대기 항목

이 파일은 `iocs/` 트래커가 발견했지만 아직 `SearchStrike-Checker.ps1`에 반영되지 않은 지표를 누적 기록합니다.
`SearchStrike-Checker.ps1` / `.bat` / `.md`는 이 트래커가 직접 수정하지 않습니다 — 아래 항목은 사람이 수작업으로 반영해야 합니다.

## 반영 대기 항목 없음

2026-08-31 기준: 최초 실행에서 수집된 모든 지표는 `.ps1`의 `$IOC_Hashes`, `$IOC_C2Domains`, `$ETH_RPC_Hosts` 배열에서 그대로 추출한 시드 데이터이며, 시드 이외의 신규 지표는 발견되지 않았습니다. 스크립트는 현재 최신 상태입니다.

2026-09-11 기준: `iocs/`에 신규로 채택된 지표가 없어 스크립트 반영 대상도 여전히 없습니다. (참고: GitHub `PJO2/tftpd64` 이슈 #46에서 발견한 가짜 Tftpd64 해시 6건은 SearchStrike와의 연관이 확인되지 않아 `iocs/`에도 채택하지 않았으므로 이 목록에도 포함하지 않음 — 상세는 `snapshots/2026-09-11.md` 참고.)

2026-09-12 기준: 이번 실행에서도 페치 8건이 모두 차단/실패하여 신규 검증 지표가 없었고, `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-13 기준: 이번 실행에서는 페치 8건 중 1건(microsoft.com)만 성공했으나 SearchStrike와 무관한 별개 캠페인(Silver Fox)이었고, 나머지 7건은 모두 차단/실패했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-14 기준: 이번 실행에서는 페치 9건 중 1건(github.com/PJO2/tftpd64 issue #46)만 성공했으나 이전 실행에서 이미 검토·미채택 처리된 동일 해시 재확인이었고, 한국 소스 5곳은 모두 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-15 기준: 이번 실행에서는 페치 8건 중 1건(microsoft.com)만 성공했으나 SearchStrike와 무관한 별개 캠페인(Silver Fox)이었고, 나머지 7건(thorcert.notion.site 포함)은 모두 차단되었습니다. THORCert 원문 헌팅 가이드 URL을 이번에 처음 특정했으나 아직 본문을 확인하지 못했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-16 기준: 이번 실행에서는 페치 8건(신규 EtherRAT 2차 보도 6건 + 한국 소스 2곳 최초 시도)이 전부 차단되어 성공한 페치가 없었습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-17 기준: 이번 실행에서는 페치 8건 중 2건(microsoft.com, cloud.google.com)이 성공했으나 둘 다 SearchStrike와 무관한 별개 캠페인(각각 Philips 위장 가짜 다운로더 캠페인, UNC5342/DPRK Contagious Interview)으로 확인되어 검증 근거로 사용하지 않았고, 나머지 6건(THORCert 원문 포함)은 차단/실패했습니다. 한국 소스 5곳(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr, sk-shieldus.com) 전부 이번까지 시도를 마쳤으나 접근 가능한 곳이 없었습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-18 기준: 이번 실행에서는 신규 2차 보도 소스 5건(cybersecuritynews.com, malwarebytes.com, guidepointsecurity.com, infosecurity-magazine.com, govextra.gov.il)을 처음 특정했으나 페치 8건 전부 차단되어 본문을 확인하지 못했고, krcert.or.kr·esentire.com·thorcert.notion.site 재시도도 모두 차단되었습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-19 기준: 이번 실행에서는 새로운 2차 보도 후보 5건(scworld.com, cointrust.com, mexc.com, crimson7.io, elastic.co)을 처음 특정했으나 전부 차단되었고, krcert.or.kr 재시도도 차단되었습니다. 페치에 성공한 2건(microsoft.com, github.com/PJO2/tftpd64 issue #46)은 각각 SearchStrike와 무관한 별개 캠페인(Silver Fox)과 기존에 이미 검토·미채택된 가짜 Tftpd64 해시 재확인이었습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-20 기준: 이번 실행에서는 신규 한국 소스 후보 1건(cyberone.kr)과 2차 보도 후보 5건(teamwin.in, govextra.gov.il, guidepointsecurity.com, infosecurity-magazine.com, malwarebytes.com)을 처음 시도했으나 페치 8건 전부 차단되어 본문을 확인하지 못했고, krcert.or.kr 재시도도 차단되었습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-21 기준: 이번 실행에서는 microsoft.com 신규 블로그(2026-09-01자)를 처음 페치했으나 SearchStrike와 무관한 별개 캠페인(Silver Fox 계열 가짜 설치파일)으로 확인되어 미채택했고, cloud.google.com 추정 URL은 404였습니다. 한국 소스 5곳 중 4곳(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr)은 이번에도 차단되었고 cyberone.kr·sk-shieldus.com은 DNS 조회 자체가 실패했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-22 기준: 이번 실행에서는 WebSearch로 thedfirreport.com의 신규 게시물(EtherRAT/TukTuk C2 관련, 2026-05-11자)을 처음 발견했으나 페치가 차단되어 본문을 확인하지 못했고, cloud.google.com `dprk-adopts-etherhiding` 페치는 성공했으나 SearchStrike와 무관한 별개 캠페인(UNC5342/Contagious Interview)으로 확인되어 미채택했습니다. 한국 소스 6곳(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr, sk-shieldus.com) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-23 기준: 이번 실행에서는 신규 2차 보도 후보 2건(cybersecuritynews.com "New EtherRAT Variant Uses Trojanized Tftpd64 Installer", malwarebytes.com "Inside a malicious infrastructure delivering EtherRAT")을 처음 특정했으나 페치 8건 전부 차단/실패(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패)되어 본문을 확인하지 못했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-24 기준: 이번 실행에서는 신규 2차 보도 후보 1건(esentire.com "EtherRAT & SYS_INFO Module: C2 on Ethereum (EtherHiding), Target Selection, CDN-Like Beacons")을 처음 특정했으나 페치가 차단되어 본문을 확인하지 못했습니다. microsoft.com의 신규 2026-09-01자 블로그("Counterfeit installers to system compromise")는 페치에 성공했으나 SearchStrike와 무관한 별개 캠페인(Razer/Edge/Kaspersky 위장 가짜 다운로드 사이트, 중국 기반 표적)으로 확인되어 미채택했습니다. 한국 소스 6곳(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr, sk-shieldus.com) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-25 기준: 이번 실행에서는 신규 2차 보도 후보 2건(cribl.io "Cribl SecOps uncovers EtherHiding malware campaign on the blockchain", socprime.com "ChainScript: Tracing a Node.js RAT Through the Blockchain")을 처음 특정했으나 페치 8건 전부 차단/실패(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr, cribl.io, socprime.com은 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패)되어 본문을 확인하지 못했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-26 기준: 이번 실행에서는 기존에 이미 특정된 2차 보도(cybersecuritynews.com, scworld.com, teamwin.in, malwarebytes.com, govextra.gov.il, guidepointsecurity.com, infosecurity-magazine.com, cribl.io, socprime.com, crimson7.io, esentire.com)만 검색 결과에 재확인되었고 신규 후보는 없었습니다. microsoft.com 검색 페이지는 이번에 응답했으나 관련 결과가 0건이었고, esentire.com 페치는 차단되었습니다. 한국 소스 6곳(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패)은 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-27 기준: 이번 실행에서는 신규 후보로 ransom-isac.org "XCTDH Adopts Hash Hiding"를 발견했으나 SearchStrike/EtherRAT와 무관한 별개 캠페인(XCTDH)으로 확인되어 미채택했습니다. microsoft.com은 이번에도 응답했으나 관련 결과 0건이었고, esentire.com 재시도를 포함해 나머지 페치는 모두 차단/실패(한국 소스 6곳 전부 접근 불가)했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-28 기준: 이번 실행에서는 microsoft.com(2026-09-01자 블로그 재확인)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 둘 다 SearchStrike/EtherRAT와 무관한 별개 캠페인(각각 Razer/Edge/Kaspersky 위장 가짜 다운로드 사이트, DPRK/UNC5342 JADESNOW)으로 확인되어 미채택했습니다. 한국 소스 5곳(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-29 기준: 이번 실행에서는 신규 한국어 2차 소스 후보 1건(cyberone.kr "개발자 대상 유틸리티 도구로 위장한 악성코드 유포 주의 권고")을 처음 특정했으나 페치가 차단되어 본문을 확인하지 못했습니다. microsoft.com 블로그 검색은 응답했으나 관련 게시물 0건이었고, cloud.google.com "UNC5142 Leverages EtherHiding" 페치는 성공했으나 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5142, WordPress 경유 인포스틸러 유포)으로 확인되어 미채택했습니다. 한국 소스 6곳(cyberone.kr, krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-09-30 기준: 이번 실행에서는 esentire.com("EtherRAT & SYS_INFO Module") 재시도가 차단되었고, 이더리움 RPC C2 검색에서 신규 후보(ransom-isac.org, gbhackers.com, cyberupdates365.com, cyberpress.org)가 나타났으나 모두 XCTDH/HashHiding이라는 별개의 DPRK 연계 캠페인으로 확인되어 미채택했습니다. microsoft.com 블로그 검색은 응답했으나 관련 게시물 0건이었고, 한국 소스 6곳(cyberone.kr, krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 스크립트 반영 대상도 여전히 없습니다.

2026-10-01 기준: 이번 실행에서는 microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 후자는 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5342/Contagious Interview)으로 확인되어 미채택했습니다. KISA 헌팅 가이드 관련 WebSearch 스니펫에서 네트워크 침해지표로 커스텀 HTTP 헤더 `X-Bot-Server`가 처음 언급됨을 확인했으나(원문 boho.or.kr 페치는 차단), 이는 `$IOC_Hashes`/`$IOC_C2Domains`/`$ETH_RPC_Hosts` 배열 항목이 아니라 네트워크 요청 헤더 검사 로직에 해당하는 사안이며 아직 미검증 상태입니다 — 원문이 확인되면 스크립트에 HTTP 헤더 검사 추가를 검토할 근거로 기록해 둡니다. 한국 소스 6곳(boho.or.kr, cyberone.kr, krcert.or.kr, asec.ahnlab.com, igloo.co.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

2026-10-02 기준: 이번 실행에서는 신규 2차 보도 후보 1건(cybersecuritynews.com "Hackers Turned Ethereum Into a Secret Messaging System for Malware")을 처음 특정했으나 페치가 차단되어 SearchStrike와의 연관 여부를 확인하지 못했습니다. microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding", 무관한 별개 캠페인으로 재확인) 페치는 성공했습니다. 한국 소스 6곳(boho.or.kr, krcert.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

2026-10-03 기준: 이번 실행에서는 microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 후자는 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5342/JADESNOW)으로 확인되어 미채택했습니다. WebSearch 스니펫에서 KISA 헌팅 가이드의 `rpc.mevblock.io`/`X-Bot-Server` 언급이 재확인되었으나 원문(boho.or.kr) 페치는 계속 차단되어 기존 미검증 상태에서 변화가 없습니다. 한국 소스 6곳(boho.or.kr, krcert.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

2026-10-04 기준: 이번 실행에서는 microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 후자는 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5342/JADESNOW)으로 확인되어 미채택했습니다. 한국 소스 6곳(boho.or.kr, krcert.or.kr, asec.ahnlab.com, igloo.co.kr, cyberone.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

2026-10-05 기준: 이번 실행에서는 보호나라(boho.or.kr) 공지 2건의 특정 URL(nttId=71998, nttId=27369)과 cyberone.kr 기사(id=128389)를 처음으로 직접 페치 시도했으나 전부 차단되어 본문을 확인하지 못했습니다. mexc.com "EtherRAT Malware Targets Windows Through Fake Tftpd64 Installer"를 신규 후보로 WebSearch에서 발견했으나 미페치 상태입니다. microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 후자는 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5342/JADESNOW)으로 재확인되어 미채택했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

2026-10-06 기준: 이번 실행에서는 microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 후자는 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5342/JADESNOW)으로 재확인되어 미채택했습니다. 한국 소스 6곳(boho.or.kr, cyberone.kr, krcert.or.kr, asec.ahnlab.com, igloo.co.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

2026-10-07 기준: 이번 실행에서는 microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 후자는 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5342/JADESNOW/UNC5142)으로 재확인되어 미채택했습니다. 신규 2차 보도 후보 1건(securityarsenal.com "GlassWorm, EtherRAT and RebEx RAT: Blockchain C2 and Multi-Stage Supply Chain Attacks")을 처음 특정했으나 페치가 차단되어 SearchStrike와의 연관 여부를 확인하지 못했습니다. 한국 소스 5곳(boho.or.kr, krcert.or.kr, asec.ahnlab.com, igloo.co.kr는 EGRESS_BLOCKED, sk-shieldus.com은 DNS 조회 실패) 전부 이번에도 접근 불가했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

2026-10-08 기준: 이번 실행에서는 microsoft.com(관련 게시물 0건)과 cloud.google.com("DPRK adopts EtherHiding") 페치에 성공했으나 후자는 SearchStrike/EtherRAT와 무관한 별개 캠페인(UNC5342/JADESNOW/UNC5142)으로 재확인되어 미채택했습니다. WebSearch에서 GoCaracal, DeadLock, macOS EtherHiding(Prophet Security), SafeDep TTP 문서 등 블록체인 C2 관련 신규 글을 발견했으나 전부 SearchStrike와 무관한 별개 패밀리이거나 일반 기법 설명이라 미채택했습니다. 한국 소스 5곳(krcert.or.kr, boho.or.kr, asec.ahnlab.com, igloo.co.kr, sk-shieldus.com)과 신규 시도한 safedep.io 전부 DNS 조회 자체가 실패해 접근 불가했고, securityarsenal.com(전날 특정한 GlassWorm/EtherRAT/RebEx 기사)도 이번에는 DNS 조회가 실패했습니다. `iocs/`에 신규 채택 지표가 없어 배열 반영 대상은 여전히 없습니다.

향후 실행에서 신규 검증/미검증 지표가 발견되면 여기에 배열명(`$IOC_Hashes` / `$IOC_C2Domains` / `$ETH_RPC_Hosts`)과 최초 발견일을 함께 기록합니다.
