from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static # Import the home view

# এই লাইনটা যোগ করুন (যদি আগে না থাকে)
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent

# আপনার আগের কোডে যেটা ছিল তা মুছে এটা বসান


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('authentication.urls')),
    path('api/attorney/', include('attorney.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)