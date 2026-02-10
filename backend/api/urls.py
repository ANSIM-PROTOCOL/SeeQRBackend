
from django.urls import path
from api.views import QrScanView, GenerateReportView, InquireView, DashboardView, InquireEditView, LoginView


urlpatterns = [
    path('qr-scan/', QrScanView.as_view(), name='qr-scan'),
    path('report/', GenerateReportView.as_view(), name='generate-report'),
    path('inquire/', InquireView.as_view(), name='inquire'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('inquire/<int:inquire_id>/edit/', InquireEditView.as_view(), name='inquire-edit'),
    path('login/', LoginView.as_view(), name='login'),
]
