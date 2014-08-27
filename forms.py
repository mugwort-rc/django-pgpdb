from django import forms
from django.utils.translation import ugettext_lazy as _

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
    options = forms.CharField(
        required=False,
        widget=forms.HiddenInput(attrs={'disabled': 'disabled'})
    )

class KeyServerLookupForm(forms.Form):
    op = forms.RegexField(
        r'(?i)(get|index|vindex|x-.+|)',
        required=False,
        widget=forms.RadioSelect(
            choices=(
                ('index', _('Index')),
                ('vindex', _('Verbose Index'))
            )
        ),
        label=_('Search operation'),
        initial='vindex'
    )
    search = forms.CharField()
    options = forms.CharField(
        required=False, widget=forms.HiddenInput(attrs={'disabled': 'disabled'})
    )
    fingerprint = forms.RegexField(
        r'(?i)(on|off|)',
        required=False,
        widget=forms.CheckboxInput(attrs={'checked': 'checked', 'value': 'on'}),
        label=_('Show fingerprint')
    )
    exact = forms.RegexField(
        r'(?i)(on|off|)',
        required=False,
        widget=forms.CheckboxInput(attrs={'value': 'on'}),
        label=_('Exact match')
    )

