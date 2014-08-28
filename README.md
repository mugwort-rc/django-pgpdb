django-pgpdb
============

## Usage

```
urlpatterns = patterns('',
    # PGP Key Server
    url(r'^pks/', include('pgpdb.urls')),
)
```

