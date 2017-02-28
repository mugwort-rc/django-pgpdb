from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r"^$", views.index, name="index"),
    url(r"^add$", views.add, name="add"),
    url(r"^lookup$", views.lookup, name="lookup"),
]
