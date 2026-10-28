from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from investigations.views import api_health

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("login/", RedirectView.as_view(pattern_name="login", permanent=False)),
    path("api/health", api_health, name="api_health"),
    path("", include("investigations.urls")),
]

