@echo off

cd /d "%~dp0backend"

start "run_server" uv run python manage.py makemigrations
start "apply_migrations" uv run python manage.py migrate