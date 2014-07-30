from django.contrib import admin

import models

class PGPKeyModelAdmin(admin.ModelAdmin):
    list_display = ('uid', 'compromised', 'crc24', 'file',)
    exclude      = ('uid', 'crc24',)

admin.site.register(models.PGPKeyModel, PGPKeyModelAdmin)

