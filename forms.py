from django import forms

import models

class PGPUserIDModelForm(forms.ModelForm):
    class Meta:
        model = models.PGPUserIDModel
        fields = ('name', 'comment', 'email',)
        widgets = {
            'name': forms.TextInput(),
            'comment': forms.TextInput(),
            'email': forms.TextInput(),
        }

