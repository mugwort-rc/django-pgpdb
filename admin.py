from django.contrib import admin

import forms
import models

class PGPKeyModelAdmin(admin.ModelAdmin):
    list_display = ('uid', 'user', 'user_ids', 'key_id', 'compromised', 'crc24', 'file',)
    exclude      = ('uid', 'crc24',)

    def user_ids(self, obj):
        html = ''
        for userid in obj.userids.all():
            html += '<li><a href="../pgpuseridmodel/{0}/">{1}</a></li>'.format(userid.id, userid.userid)
        return '<ul>{0}</ul>'.format(html)
    user_ids.allow_tags = True

    def key_id(self, obj):
        html = ''
        for pub in obj.public_keys.all():
            html += '<li>{0}</li>'.format(pub.keyid)
        return '<ul>{0}</ul>'.format(html)
    key_id.allow_tags = True

admin.site.register(models.PGPKeyModel, PGPKeyModelAdmin)

class PGPUserIDModelAdmin(admin.ModelAdmin):
    form = forms.PGPUserIDModelForm
    list_display = ('userid',)

admin.site.register(models.PGPUserIDModel, PGPUserIDModelAdmin)

