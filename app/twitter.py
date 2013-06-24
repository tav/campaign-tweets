# Public Domain (-) 2009-2013 The TweetApp Authors.
# See the TweetApp UNLICENSE file for details.

"""
Twitter API Client.

To start, initialise a client with the consumer key and
secret for your app, e.g.

    >>> client = Client(CONSUMER_KEY, CONSUMER_SECRET)

If you already have the access token and secret for a user,
you can instantiate a subclient with:

    >>> subclient = client.for_auth(token, secret)

You can then make API calls by using dot notation for the
URL path segments of the Twitter API method and keyword
arguments for the parameters, e.g.

    >>> subclient.statuses.show(id=123, trim_user=True)
    <urlfetch.Response object>

    >>> subclient.statuses.update(status="Hello world!")
    <urlfetch.Response object>

    >>> subclient.friendships.lookup(screen_name="tav")
    <urlfetch.Response object>

By default the raw ``urlfetch.Response`` object is returned,
but you can auto-decode JSON responses into Python objects
by calling the ``json`` method on the response, e.g.

    >>> subclient.friendships.lookup(screen_name="tav").json()
    [{"name": "tav", "id_str": ...}]

Some internals are exposed for your convenience. By default,
all requests time out after 20 seconds. You can modify this
by setting the ``deadline`` attribute on a ``client``:

    >>> client.deadline = 40

Or if you wanted to modify the deadline globally for all
clients:

    >>> Client.deadline = 40

Do bear in mind that App Engine limits urlfetch requests to
a maximum of 60 seconds within frontend requests and to 10
minutes for cron and taskqueue requests.

You can also access the attributes ``authenticate_url`` and
``authorize_url`` in order to send users to the appropriate
auth URL on Twitter, e.g.

    >>> url = client.authorize_url + "?oauth_token=" + token

These attributes are also writable. So you can modify them
should you wish to use an alternative endpoint of some kind.

"""

from binascii import hexlify
from hashlib import sha1
from hmac import new as hmac
from json import loads
from os import urandom
from time import time
from urllib import quote as urlquote, urlencode

from google.appengine.api.urlfetch import (
    GET, POST, create_rpc, fetch, make_fetch_call
    )

def encode(param):
    if isinstance(param, unicode):
        param = param.encode('utf-8')
    else:
        param = str(param)
    return urlquote(param, '')

def decode_json(resp):
    if resp.status_code != 200:
        if resp.status_code == 429:
            get = resp.headers.get
            raise RateLimitError(
                int(get('X-Rate-Limit-Limit', 0)),
                int(get('X-Rate-Limit-Remaining', 0)),
                int(get('X-Rate-Limit-Reset', 0)),
                )
        raise RequestError(resp)
    return loads(resp.content)

class Client(object):
    """A client for the Twitter API."""

    deadline = 20.0

    api_base_url = "https://api.twitter.com/1.1/"
    access_token_url = "https://api.twitter.com/oauth/access_token"
    authenticate_url = "https://api.twitter.com/oauth/authenticate"
    authorize_url = "https://api.twitter.com/oauth/authorize"
    request_token_url = "https://api.twitter.com/oauth/request_token"

    post_methods = frozenset([
        'account/remove_profile_banner',
        'account/settings',
        'account/update_delivery_device',
        'account/update_profile',
        'account/update_profile_background_image',
        'account/update_profile_banner',
        'account/update_profile_colors',
        'account/update_profile_image',
        'blocks/create',
        'blocks/destroy',
        'direct_messages/destroy',
        'direct_messages/new',
        'favorites/create',
        'favorites/destroy',
        'friendships/create',
        'friendships/destroy',
        'friendships/update',
        'geo/place',
        'lists/create',
        'lists/destroy',
        'lists/members/create',
        'lists/members/create_all',
        'lists/members/destroy',
        'lists/members/destroy_all',
        'lists/subscribers/create',
        'lists/subscribers/destroy',
        'lists/update',
        'saved_searches/create',
        'saved_searches/destroy',
        'statuses/destroy',
        'statuses/filter',
        'statuses/update_with_media',
        'users/report_spam'
        ])

    def __init__(
        self, consumer_key, consumer_secret, oauth_token=None,
        oauth_secret=None
        ):
        self._key = consumer_key
        self._secret = consumer_secret
        self._oauth_token = oauth_token
        self._oauth_secret = oauth_secret

    def __getattr__(self, attr):
        return Proxy(self, attr)

    def __call__(self, path, return_rpc=False, **kwargs):
        return self._call_explicitly(
            path, self._oauth_token, self._oauth_secret, return_rpc=return_rpc,
            **kwargs
            )

    def _call_explicitly(
        self, path, oauth_token=None, oauth_secret=None, oauth_callback=None,
        is_post=False, return_rpc=False, **kwargs
        ):

        params = {
            'oauth_consumer_key': self._key,
            'oauth_nonce': hexlify(urandom(18)),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time())),
            'oauth_version': '1.0'
        }

        key = self._secret + '&'
        if oauth_token:
            params['oauth_token'] = oauth_token
            key += encode(oauth_secret)
        elif oauth_callback:
            params['oauth_callback'] = oauth_callback

        params.update(kwargs)

        if not (path.startswith('https://') or path.startswith('http://')):
            path = self.api_base_url + path + ".json"

        if not is_post:
            is_post = path in self.post_methods
            if not is_post:
                spath = path.split('/')
                npath = ''            
                while spath:
                    if npath:
                        npath += '/' + spath.pop(0)
                    else:
                        npath = spath.pop(0)
                    if npath in self.post_methods:
                        is_post = True
                        break

        if is_post:
            meth = POST
            meth_str = 'POST'
        else:
            meth = GET
            meth_str = 'GET'

        message = '&'.join([
            meth_str, encode(path), encode('&'.join(
                '%s=%s' % (k, encode(params[k])) for k in sorted(params)
                ))
            ])

        params['oauth_signature'] = hmac(
            key, message, sha1
            ).digest().encode('base64')[:-1]

        auth = ', '.join(
            '%s="%s"' % (k, encode(params[k])) for k in sorted(params)
            if k not in kwargs
            )

        headers = {'Authorization': 'OAuth %s' % auth}
        if is_post:
            payload = urlencode(kwargs)
        else:
            path += '?' + urlencode(kwargs)
            payload = None

        if return_rpc:
            rpc = create_rpc(self.deadline)
            make_fetch_call(
                rpc, path, payload, meth, headers, validate_certificate=True
                )
            return rpc

        resp = fetch(
            path, payload, meth, headers, deadline=self.deadline,
            validate_certificate=True
            )
        resp.json = decode_json
        return resp

    def get_access_token(self, oauth_token, oauth_secret, oauth_verifier):
        resp = self._call_explicitly(
            self.access_token_url, oauth_token, oauth_secret, is_post=True,
            oauth_verifier=oauth_verifier
            )
        if resp.status_code != 200:
            raise RequestError(resp)
        return dict(tuple(param.split('=')) for param in resp.content.split('&'))

    def get_request_token(self, oauth_callback):
        resp = self._call_explicitly(
            self.request_token_url, oauth_callback=oauth_callback,
            is_post=True
            )
        if resp.status_code != 200:
            raise RequestError(resp)
        return dict(tuple(param.split('=')) for param in resp.content.split('&'))

    def for_auth(self, token, secret):
        return Client(self._key, self._secret, token, secret)

class Proxy(object):
    """Access Twitter API methods via dot.notation attribute access."""

    __slots__ = ('_client', '_path')

    def __init__(self, client, path):
        self._client = client
        self._path = path

    def __getattr__(self, attr):
        return Proxy(self._client, self._path + '/' + attr)

    def __call__(self, *args, **kwargs):
        return self._client(self._path, *args, **kwargs)

class RateLimitError(Exception):
    """Rate Limit reached when making a Twitter API call."""

    def __init__(self, limit, remaining, reset):
        self.limit = limit
        self.remaining = remaining
        self.reset = reset

class RequestError(Exception):
    """Error making a Twitter API call."""

    def __init__(self, resp):
        self.resp = resp
