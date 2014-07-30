import os
import base64

from django.conf import settings
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import models
from django.db.models.signals import class_prepared, post_save, post_delete

import pgpdump
from pgpdump.utils import crc24, PgpdumpException

from django_extensions.db.fields import UUIDField

def register_file(path, data):
    return default_storage.save(path, ContentFile(data))

def unregister_file(fp):
    path = os.path.dirname(fp.path)
    default_storage.delete(fp)
    if len(os.listdir(path)) != 0:
        return
    try:
        os.rmdir(path)
    except OSError:
        pass

def read_file(fp):
    return default_storage.open(fp).read()

def update_file(fp, data):
    f = default_storage.open(fp, 'wb')
    f.write(data)
    f.close()

class PGPKeyModelManager(models.Manager):

    PGP_KEY_STORAGE = 'pgpdb/{0}/{1}.pgp'

    def contribute_to_class(self, model, name):
        super(PGPKeyModelManager, self).contribute_to_class(model, name)
        class_prepared.connect(self.class_prepared, sender=self.model)

    def class_prepared(self, sender, **kwargs):
        post_save.connect(self.post_save, sender=self.model)
        post_delete.connect(self.post_delete, sender=self.model)

    def post_save(self, sender, instance, created, **kwargs):
        if created:
            data = read_file(instance.file)
            pgp = None
            try:
                pgp = pgpdump.AsciiData(data)
            except PgpdumpException:
                pgp = pgpdump.BinaryData(data)
            update_file(instance.file, pgp.data)
            crc = crc24(pgp.data)
            crc_bin = ''.join([chr((crc >> i) & 0xff) for i in [16, 8, 0]])
            instance.crc24 = base64.b64encode(crc_bin)
            instance.save()

    def post_delete(self, sender, instance, **kwargs):
        """
            \sa: self.save_to_storage()
        """
        unregister_file(instance.file)

    def save_to_storage(self, user, data):
        return self.create(user=user, file=ContentFile(data))

def _pgp_key_model_upload_to(instance, filename):
    uid = instance.uid
    path = PGPKeyModelManager.PGP_KEY_STORAGE.format(uid[:2], uid[2:])
    return os.path.join(settings.MEDIA_ROOT, path)

class PGPKeyModel(models.Model):
    uid = UUIDField()
    user = models.ForeignKey(User)
    file = models.FileField(upload_to=_pgp_key_model_upload_to, storage=default_storage)
    crc24 = models.CharField(max_length=4)  # =([A-Za-z0-9+/]{4})
    compromised = models.BooleanField(default=False)

    objects = PGPKeyModelManager()

class PGPPublicKeyModel(models.Model):
    key = models.ForeignKey('PGPKeyModel', related_name='public_keys')
    sub = models.BooleanField(default=False)

class PGPPublicKeyInfoModel(models.Model):
    public_key = models.ForeignKey('PGPPublicKeyModel', related_name='info')
    creation_time = models.DateTimeField()
    expiration_time = models.DateTimeField(null=True)
    algorithm = models.IntegerField()
    fingerprint = models.CharField(max_length=40)
    keyid = models.CharField(max_length=16)
