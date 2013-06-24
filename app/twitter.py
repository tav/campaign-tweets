# Public Domain (-) 2013 The Campaign Tweets Authors.
# See the Campaign Tweets UNLICENSE file for details.

"""Twitter API Client."""

import logging

from binascii import hexlify
from hashlib import sha1
from hmac import new as hmac
from json import loads as decode_json
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

def to_json(resp):
    if resp.status_code != 200:
        if resp.status_code == 429:
            hdrs = resp.headers
            raise RateLimitError(
                int(hdrs.get('X-Rate-Limit-Limit', 0)),
                int(hdrs.get('X-Rate-Limit-Remaining', 0)),
                int(hdrs.get('X-Rate-Limit-Reset', 0)),
                )
        raise RequestError(resp)
    return decode_json(resp.content)

class Client(object):
    """A client for the Twitter API."""

    _deadline = 20.0

    _api_base_url = "https://api.twitter.com/1.1/"
    _access_token_url = "https://api.twitter.com/oauth/access_token"
    _authenticate_url = "https://api.twitter.com/oauth/authenticate"
    _authorize_url = "https://api.twitter.com/oauth/authorize"
    _request_token_url = "https://api.twitter.com/oauth/request_token"

    _post_methods = frozenset([
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

    def __init__(self, key, secret, auth_token=None, auth_secret=None):
        self._key = key
        self._secret = secret
        self._auth_token = token
        self._auth_secret = secret

    def __getattr__(self, attr):
        return Proxy(self, attr)

    def __call__(self, path, return_rpc=False, **kwargs):
        return self.call(
            path, self._auth_token, self._auth_secret, return_rpc, **kwargs
            )

    def call(       
        self, path, oauth_token=None, oauth_secret=None, oauth_callback=None,
        return_rpc=False, **kwargs
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

        if path.startswith('https://'):
            is_post = True
        else:
            path = self._api_base_url + path + ".json"
            is_post = False

        if not is_post:
            is_post = path in self._post_methods
            if not is_post:
                spath = path.split('/')
                npath = ''            
                while spath:
                    if npath:
                        npath += '/' + spath.pop(0)
                    else:
                        npath = spath.pop(0)
                    if npath in self._post_methods:
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
            rpc = create_rpc(self._deadline)
            make_fetch_call(
                rpc, path, payload, meth, headers, validate_certificate=True
                )
            return rpc

        resp = fetch(
            path, payload, meth, headers, deadline=self._deadline,
            validate_certificate=True
            )
        resp.json = to_json
        return resp

    def get_access_token(self, oauth_token, oauth_secret, oauth_verifier):
        resp = self.call(
            self._access_token_url, oauth_token, oauth_secret,
            oauth_verifier=oauth_verifier
            )
        if resp.status_code != 200:
            raise RequestError(resp)
        return dict(tuple(param.split('=')) for param in resp.content.split('&'))

    def get_request_token(self, oauth_callback):
        resp = self.call(self._request_token_url, oauth_callback=oauth_callback)
        if resp.status_code != 200:
            raise RequestError(resp)
        return dict(tuple(param.split('=')) for param in resp.content.split('&'))

    def for_auth(self, token, secret):
        return Client(self._key, self._secret, token, secret)

class Proxy(object):
    """Access Twitter API methods via dot.notation attribute access."""

    __slots__ = ('_args', '_client', '_path')

    def __init__(self, client, path, *args):
        self._client = client
        self._path = path

    def __getattr__(self, attr):
        return Proxy(self._client, self._path + '/' + attr, *self._args)

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
