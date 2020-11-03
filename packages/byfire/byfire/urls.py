from django.urls import path, include

urlpatterns = [
    path('', include('controlpanel.urls')),
    path('cp/', include('controlpanel.urls')),
]
