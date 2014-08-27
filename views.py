from django.http import (
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

import forms, models

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
            pgp = pgpdump.AsciiData(keytext)
        except Exception:
            raise __AddException
        if not _is_valid_packets(pgp):
            raise __AddException
        pgpkey = models.PGPKeyModel.objects.save_to_storage(None, keytext)
        c = {
            'pgpkey': pgpkey,
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
        # display by op
        op = form.cleaned_data['op'].lower()
        op = op if op else 'index'
        if op == 'get':
            if keys.count() != 1:
                raise __LookupException
            c = {
                'key': keys[0],
            }
            return render_to_response('pgpdb/lookup_get.html', c)
        elif op in ['index', 'vindex']:
            if keys.count() == 0:
                raise __LookupException
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

def _is_valid_packets(pgp):
    pubkey = 0  # (1 <= pubkey) / One Public-Key packet
    revsig = 0  # (0 <= revsig) / Zero or more revocation signatures
    userid = 0  # (1 <= userid) / One or more User ID packets
    pubsig = 0  # (0 <= pubsig) / After each User ID packet, zero or more Signature packets (certifications)
    usratt = 0  # (0 <= usratt) / Zero or more User Attribute packets
    attsig = 0  # (0 <= attsig) / After each User Attribute packet, zero or more Signature packets (certifications)
    subkey = 0  # (0 <= subkey) / Zero or more Subkey packets
    subsig = 0  # (0 <= subsig) / After each Subkey packet, one Signature packet,
    aftrev = 0  # plus optionally a revocation
    other  = 0
    packets = [x for x in pgp.packets()]
    length  = len(packets)
    for i in range(length):
        packet = packets[i]
        if i == 0 and isinstance(packet, PublicKeyPacket):
            pubkey = 1
        elif pubkey == 1:
            if ( userid == 0 and
                 isinstance(packet, SignaturePacket) and
                 packet.raw_sig_type == 0x30):
                revsig += 1
            elif ( userid >= 0 and
                   isinstance(packet, UserIDPacket)):
                userid += 1
            elif ( userid > 0 and usratt == 0 and
                   ( isinstance(packets[i-1], UserIDPacket) or
                     ( isinstance(packets[i-1], SignaturePacket) and
                       packets[i-1].raw_sig_type in [0x10, 0x11, 0x12, 0x13]
                     )
                   ) and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type in [0x10, 0x11, 0x12, 0x13]):
                pubsig += 1
            elif ( userid > 0 and
                   isinstance(packet, UserAttributePacket)):
                usratt += 1
            elif ( usratt > 0 and
                   ( isinstance(packets[i-1], UserAttributePacket) or
                     ( isinstance(packets[i-1], SignaturePacket) and
                       packets[i-1].raw_sig_type in [0x10, 0x11, 0x12, 0x13]
                     )
                   ) and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type in [0x10, 0x11, 0x12, 0x13]):
                attsig += 1
            elif isinstance(packet, PublicSubkeyPacket):
                subkey += 1
            elif ( subkey > 0 and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type == 0x18):
                subsig += 1
            elif ( subkey > 0 and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type in [0x20, 0x28, 0x30]):
                aftrev += 1
            else:
                other += 1
    return other == 0

