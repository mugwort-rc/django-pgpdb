from django.conf.urls import patterns, include, url

urlpatterns = patterns('',
    url(r'^$', 'pgpdb.views.index', name='pgpkeyserver'),
    url(r'^add$', 'pgpdb.views.add'),
    url(r'^lookup$', 'pgpdb.views.lookup'),
)
