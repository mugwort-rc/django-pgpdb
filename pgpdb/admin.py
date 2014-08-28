from django.contrib import admin

import forms
import models

class PGPKeyModelAdmin(admin.ModelAdmin):
    list_display = ('uid', 'user', 'user_ids', 'key_id', 'is_revoked', 'crc24', 'file',)
    exclude = ('uid', 'crc24',)
    list_filter = ('is_revoked',)
    search_fields = ('uid', 'userids__userid', 'public_keys__keyid',)

    def user_ids(self, obj):
        html = ''
        for userid in obj.userids.all():
            html += '<li><a href="../pgpuseridmodel/{0}/">{1}</a></li>'.format(userid.id, userid.userid)
        return '<ul>{0}</ul>'.format(html)
    user_ids.allow_tags = True

    def key_id(self, obj):
        html = ''
        for pub in obj.public_keys.all():
            html += '<li><a href="../pgppublickeymodel/?q={0}">{0}</a></li>'.format(pub.keyid)
        return '<ul>{0}</ul>'.format(html)
    key_id.allow_tags = True

admin.site.register(models.PGPKeyModel, PGPKeyModelAdmin)

class PGPUserIDModelAdmin(admin.ModelAdmin):
    form = forms.PGPUserIDModelForm
    list_display = ('userid',)
    search_fields = ('userid',)

admin.site.register(models.PGPUserIDModel, PGPUserIDModelAdmin)

class PGPPublicKeyModelAdmin(admin.ModelAdmin):
    list_display = ('key_uid', 'keyid', 'fingerprint', 'algorithm', 'is_sub', 'creation_time', 'expiration_time',)
    list_display_links = ('keyid',)
    list_filter = ('is_sub',)
    search_fields = ('key__uid', 'keyid', 'fingerprint',)

    def key_uid(self, obj):
        return '<a href="../pgpkeymodel/?q={0}">{0}</a>'.format(obj.key.uid)
    key_uid.allow_tags = True

admin.site.register(models.PGPPublicKeyModel, PGPPublicKeyModelAdmin)

