@echo off

cd /d "%~dp0backend"

start "run_server" uv run python manage.py runserver 0.0.0.0:7079