from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls import include, url
from django.contrib import admin

from app.views import *
from restauth.views import *

from project.routers import HybridRouter
from django_mongoengine import mongo_admin


urlpatterns = [
    # default django admin interface (currently unused)
    url(r'^admin/', include(mongo_admin.site.urls)),
    url(r'^rest-auth/', include('restauth.urls', namespace='rest-auth')),

    # index page should be served by django to set cookies, headers etc.
    url(r'^$', index_view, {}, name='index'),
]

# let django built-in server serve static and media content
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
