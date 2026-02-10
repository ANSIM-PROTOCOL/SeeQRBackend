@echo off

cd /d "%~dp0backend"

start "redis_server" redis-server --bind 127.0.0.1 --port 6379
start "celery_worker" uv run celery -A backend worker -l INFO --pool=solo
start "celery_beat" uv run celery -A backend beat -l INFO