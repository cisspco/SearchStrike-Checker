# SCRIPT-SYNC — SearchStrike-Checker.ps1 반영 대기 항목

이 파일은 `iocs/` 트래커가 발견했지만 아직 `SearchStrike-Checker.ps1`에 반영되지 않은 지표를 누적 기록합니다.
`SearchStrike-Checker.ps1` / `.bat` / `.md`는 이 트래커가 직접 수정하지 않습니다 — 아래 항목은 사람이 수작업으로 반영해야 합니다.

## 반영 대기 항목 없음

2026-08-31 기준: 이번 실행(최초 실행)에서 수집된 모든 지표는 `.ps1`의 `$IOC_Hashes`, `$IOC_C2Domains`, `$ETH_RPC_Hosts` 배열에서 그대로 추출한 시드 데이터이며, 시드 이외의 신규 지표는 발견되지 않았습니다. 스크립트는 현재 최신 상태입니다.

향후 실행에서 신규 검증/미검증 지표가 발견되면 여기에 배열명(`$IOC_Hashes` / `$IOC_C2Domains` / `$ETH_RPC_Hosts`)과 최초 발견일을 함께 기록합니다.
