
<div align="center">
    <img src="./backend/api/static/logo.png"/>
    <h1>See QR 스캐너</h1>
    <h3>Python Backend Server</h3>
    <p>
        TEAM 안심 프로토콜 <br/>
        DACON 피싱·스캠 예방을 위한 서비스 개발 경진대회 예선 산출물
    </p>
    <h2>YouTube 시연 영상</h2>
    <a href="https://youtu.be/KX6N7Yd4niA">
        <img src="http://img.youtube.com/vi/KX6N7Yd4niA/0.jpg"/>
    </a>
</div>


## How to use it

1. `installer/Redis-x64-3.0.504.msi` 설치 파일을 통해 Redis 설치
2. `.env.template` 파일을 복사한 뒤, `.env` 파일 생성 후 환경 변수(API Key) 입력
3. `uv sync` 명령어를 통해 프로젝트 setting
4. `cd backend` 디렉터리 이동 후 `uv run python manage.py migrate` 명령어를 통해 마이그레이션 진행
5. `run-server.bat` 배치 스크립트를 통해 서버 실행
6. `run-celery.bat` 배치 스크립트를 통해 Celery Worker & Beat 실행
7. `See QR 스캐너` 애플리케이션을 통해 QR 스캔 진행

