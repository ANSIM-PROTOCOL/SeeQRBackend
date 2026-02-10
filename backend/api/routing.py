from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(r"^ws/reports/$", consumers.ReportStatusConsumer.as_asgi()),
    re_path(r"^ws/qr-scan/status/$", consumers.QrScanStatusConsumer.as_asgi()),
]
