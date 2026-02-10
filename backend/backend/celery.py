
import os
import sys
from celery import Celery


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings")
if any("celery" in arg.lower() for arg in sys.argv):
    # gevent/eventlet worker에서 Django ORM async-safe 가드 충돌 방지
    os.environ.setdefault("DJANGO_ALLOW_ASYNC_UNSAFE", "true")

app = Celery("backend")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
