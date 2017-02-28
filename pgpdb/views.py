from django.http import (
    HttpResponse,
    HttpResponseNotAllowed, HttpResponseBadRequest, HttpResponseNotFound
)
from django.shortcuts import render, render_to_response
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt

import pgpdump
from pgpdump.packet import (
    PublicKeyPacket, PublicSubkeyPacket, SignaturePacket, UserIDPacket,
    UserAttributePacket
)

from . import forms, models, utils

def index(request):
    c = {
        'add_form': forms.KeyServerAddForm(),
        'lookup_form': forms.KeyServerLookupForm(),
    }
    return render_to_response('pgpdb/index.html', c)

@csrf_exempt
def add(request):
    if request.method != 'POST':
        content = render(request, 'pgpdb/add_method_not_allowed.html')
        return HttpResponseNotAllowed(['POST'], content)
    form = forms.KeyServerAddForm(request.POST)
    c = {}
    try:
        if not form.is_valid():
            raise __AddException
        keytext = form.cleaned_data['keytext']
        # check keytext
        try:
            pgp = pgpdump.AsciiData(keytext.encode("utf-8", "ignore"))
        except:
            raise __AddException
        keys = utils.parse_public_key_packets(pgp)
        keytexts = []
        for data, packets in keys:
            if not utils.is_valid_packets(packets):
                raise __AddException
            keytext = utils.encode_ascii_armor(data)
            keytexts.append(keytext)
        pgpkeys = []
        for keytext in keytexts:
            pgpkey = models.PGPKeyModel.objects.save_to_storage(None, keytext)
            pgpkeys.append(pgpkey)
        c = {
            'pgpkeys': pgpkeys,
        }
    except __AddException:
        content = render(request, 'pgpdb/add_invalid_post.html')
        return HttpResponseBadRequest(content)
    return render_to_response('pgpdb/added.html', c)

def lookup(request):
    form = forms.KeyServerLookupForm(request.GET)
    try:
        if not form.is_valid():
            raise __LookupException
        search = form.cleaned_data['search']
        keys = None
        if search.startswith('0x'):
            search_ = search[2:].lower()
            query = {}
            if len(search_) in [32, 40]:
                # v3 or v4 fingerprint
                query = {
                    'public_keys__fingerprint__exact': search_,
                }
            elif len(search_) in [8, 16]:
                # 32bit or 64bit keyid
                query = {
                    'public_keys__keyid__exact': search_,
                }
            else:
                raise __LookupException
            keys = models.PGPKeyModel.objects.filter(**query)
        else:
            query = {
                'userids__userid__icontains': search,
            }
            keys = models.PGPKeyModel.objects.filter(**query)
        if keys.count() == 0:
            raise __LookupException
        # display by op
        op = form.cleaned_data['op'].lower()
        options_str = form.cleaned_data['options'].lower()
        options = [x.strip() for x in options_str.split(',')]
        if 'mr' in options:
            # machine readable response
            if op == 'get':
                resp = HttpResponse(
                    utils.keys_ascii_armor(keys),
                    content_type='application/pgp-keys'  # RFC-3156
                )
                resp['Content-Disposition'] = 'attachment; filename="pgpkey.asc"'
                return resp
            else:
                resp = HttpResponse(
                    utils.build_machine_readable_indexes(keys),
                    content_type='text/plain'
                )
                return resp
        else:
            # html response
            op = op if op else 'index'
            if op == 'get':
                c = {
                    'key': utils.keys_ascii_armor(keys),
                    'search': search,
                }
                return render_to_response('pgpdb/lookup_get.html', c)
            elif op in ['index', 'vindex']:
                c = {
                    'keys': keys,
                    'search': search,
                }
                if op == 'index':
                    return render_to_response('pgpdb/lookup_index.html', c)
                else:
                    return render_to_response('pgpdb/lookup_vindex.html', c)
    except __LookupException:
        content = render(request, 'pgpdb/lookup_not_found.html')
        return HttpResponseNotFound(content)

class __AddException(Exception):
    pass

class __LookupException(Exception):
    pass

