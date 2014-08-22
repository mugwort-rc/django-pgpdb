from django import forms

import models

class PGPUserIDModelForm(forms.ModelForm):
    class Meta:
        model = models.PGPUserIDModel
        fields = ('userid',)
        widgets = {
            'userid': forms.TextInput(),
        }

class KeyServerAddForm(forms.Form):
    keytext = forms.CharField(widget=forms.Textarea)
    # TODO: options

