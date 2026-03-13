  SearchStrike-Checker.ps1 기능 상세 설명

  공통 구조

  스크립트 실행 시 5개 섹션을 순서대로 점검하고, 결과를 화면과 로그 파일에 동시 기록

  [1/5] Filesystem → [2/5] Registry → [3/5] Process → [4/5] Network → [5/5] IOC Hash → Summary

  ------
  [1/5] 파일시스템 점검 (Invoke-FilesystemCheck)

  ① 랜덤 6자 디렉토리 내 node.exe 탐색

  %LOCALAPPDATA%\<6자 알파뉴메릭>\...\node.exe
  - %LOCALAPPDATA% 하위에서 이름이 정확히 6자 알파뉴메릭인 디렉토리를 찾음
  - 해당 디렉토리 내부를 재귀 탐색하여 node.exe 존재 여부 확인
  - 악성코드가 %LOCALAPPDATA%\GgANVN\RtoRc6\node.exe 형태로 설치되는 패턴을 탐지

  ② 고엔트로피 파일 탐지 + SHA256 로그 저장

  검색 경로: %LOCALAPPDATA%, %APPDATA%, %TEMP%
  대상 확장자: .xml .bak .cfg .bin .ini
  조건: 파일 크기 > 512B, Shannon 엔트로피 >= 7.2
  - Shannon 엔트로피를 직접 계산 (0~8 범위, 7.2 이상 = 암호화/압축 의심)
  - *\Packages\*, *\Microsoft\*, *\WindowsApps\* 경로는 Windows 정상 파일로 제외
  - 탐지 시 화면 출력과 별도로 로그에 SHA256 해시값 추가 기록 → VirusTotal 검색 활용 가능

  ③ 랜덤 이름 .cmd 파일 탐지

  검색 경로: %LOCALAPPDATA%\Temp\*.cmd
  조건: 파일명이 알파+숫자 혼합 4~16자
  - MSI 설치 과정에서 생성되는 임시 배치 스크립트 잔존 여부 확인

  ------
  [2/5] 레지스트리 점검 (Invoke-RegistryCheck)

  ① HKCU Run 키 — node.exe 실행 항목

  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  두 가지 패턴을 탐지:
  - 값(Value) 에 node.exe가 포함된 항목 → HIGH
  - 키 이름이 랜덤 Hex 문자열(80% 이상 hex 문자) + 값이 .cfg/.ini/.bin/.bak 또는 LOCALAPPDATA 경로인 항목 → MEDIUM

  ② HKLM Run 키 — node.exe 실행 항목

  HKLM\Software\Microsoft\Windows\CurrentVersion\Run
  - 시스템 전체 적용 Run 키에서 node.exe 항목 탐지 (관리자 권한 시 더 정확)

  ③ HKCU\Software 랜덤 문자열 서브키

  HKCU\Software\<랜덤 문자열>
  - MSI 설치 흔적으로 생성되는 랜덤 키 탐지
  - Wow6432Node, AppEvents 등 Windows 정상 키는 화이트리스트로 제외

  ------
  [3/5] 프로세스 점검 (Invoke-ProcessCheck)

  ① node.exe 비정상 경로 실행

  조건: node.exe 실행 경로가 LOCALAPPDATA 포함 + \nodejs\ 미포함
  - 정상적인 Node.js는 C:\Program Files\nodejs\ 또는 nvm 경로에 설치됨
  - %LOCALAPPDATA% 에서 실행 중인 node.exe는 악성 봇일 가능성

  ② 프로세스 체인 분석

  WMI(Win32_Process)로 부모-자식 프로세스 관계를 추적:

  패턴 1: msiexec.exe → cmd.exe → node.exe   (초기 감염 시)
  패턴 2: explorer.exe → node.exe             (재부팅 후 Run 키 실행 시)
  - ParentProcessId를 역추적하여 3단계 체인 전체 검증

  ③ 설정 파일 페이로드 인자 탐지

  조건: node.exe 커맨드라인에 .cfg/.ini/.bin/.bak 포함 + LOCALAPPDATA 경로
  - 악성 봇이 암호화된 설정 파일을 인자로 받아 실행하는 패턴 탐지
  - windowsHide: true로 작업표시줄에 숨겨진 실행도 커맨드라인으로 간접 탐지

  ------
  [4/5] 네트워크 점검 (Invoke-NetworkCheck)

  중요: DNS 캐시 조회를 TCP 연결 확인보다 먼저 실행하여 스크립트 자체의 DNS 조회가 캐시를 오염시키지 않도록 설계

  ① C2 도메인 DNS 캐시 흔적

  Get-DnsClientCache  # 스크립트 실행 시점의 캐시 스냅샷
  - 10개 C2 도메인이 DNS 캐시에 존재하면 과거에 해당 서버와 통신했음을 의미
  - TTL 값도 함께 기록 (TTL이 낮을수록 최근 통신)

  ② 이더리움 RPC DNS 캐시 흔적

  rpc.mevblock.io, mainnet.blockpi.network, rpc.flashbots.net 등 9개
  - 일반 업무 환경에서는 절대 발생하지 않는 트래픽
  - 블록체인 스마트 컨트랙트를 C2 채널로 사용하는 특이 패턴

  ③ C2 도메인 현재 TCP 연결

  - DNS 캐시에서 이미 해석된 IP만 사용 (신규 DNS 조회 없음)
  - 현재 Established/TimeWait/CloseWait 상태 연결과 비교

  ④ node.exe 외부 연결

  조건: node.exe PID의 TCP 연결 중 로컬(127.0.0.1, ::1) 제외한 외부 연결

  ⑤ hosts 파일 변조 확인

  - C:\Windows\System32\drivers\etc\hosts에 C2 도메인 항목 존재 여부

  ------
  [5/5] IOC 해시 점검 (Invoke-HashCheck)

  검색 경로: Downloads, Desktop, Temp, LocalAppData, AppData (각 3단계 깊이)
  대상 확장자: .msi .exe .cmd .bat .ps1 .js .vbs
  알고리즘: SHA256
  11개의 알려진 악성 파일 해시와 대조:

위장도구명: Tftpd64, (빌드일시: 2026-02-17, 02-23, 03-09, 03-10)
위장도구명: Postman, (빌드일시: 2026-02-17) 
위장도구명: WinDbg, PsExec, USMT, IntuneWinAppUtil, BgInfo, RDCMan, (빌드일시: 2026-03-10)

