
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("softsparks.co.zw/", include('core.applications.urls', namespace='applications'), name='applications')
]
