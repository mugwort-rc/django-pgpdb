django-pgpdb
============

[![Build Status](https://travis-ci.org/mugwort-rc/django-pgpdb.svg?branch=master)](https://travis-ci.org/mugwort-rc/django-pgpdb)

## Usage

```
urlpatterns = patterns('',
    # PGP Key Server
    url(r'^pks/', include('pgpdb.urls')),
)
```

## Send PGP key by gpg

```
python manage.py runserver
gpg --keyserver hkp:localhost:8000 --send-keys 0123456789ABCDEX
```

