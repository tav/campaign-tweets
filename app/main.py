# Public Domain (-) 2013 The Campaign Tweets Authors.
# See the Campaign Tweets UNLICENSE file for details.

import logging

from weblite import app, register_service, Redirect, RUNNING_ON_GOOGLE_SERVERS
from config import TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET
from twitter import Client

from google.appengine.ext import db

# -----------------------------------------------------------------------------
# Globals
# -----------------------------------------------------------------------------

client = Client(TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET)
create_key = db.Key.from_path

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

class C(db.Model):
    pass

Campaign = C

class F(db.Model):
    pass

Follower = F

class P(db.Model):
    pass

Progress = P

class R(db.Model):
    c = db.DateTimeProperty(auto_now_add=True)   # created
    s = db.StringProperty(indexed=False)         # secret

RequestToken = R

class U(db.Model):
    c = db.DateTimeProperty(auto_now_add=True)   # created
    s = db.StringProperty(indexed=False)         # oauth_token_secret
    t = db.StringProperty(indexed=False)         # oauth_token
    u = db.StringProperty()                      # screen_name

User = U

# -----------------------------------------------------------------------------
# Handlers
# -----------------------------------------------------------------------------

@register_service('/', ['home', 'site'])
def root(ctx):
    return "Hello"

@register_service('.twitter.login', [])
def twitter_login(ctx):
    info = client.get_request_token(ctx.compute_url('.twitter.auth'))
    if RUNNING_ON_GOOGLE_SERVERS:
        if info['oauth_callback_confirmed'] != 'true':
            raise Redirect('/')
    token = info['oauth_token']
    RequestToken(key_name=token, s=info['oauth_token_secret']).put()
    raise Redirect(client._authorize_url + "?oauth_token=" + token)

@register_service('.twitter.auth', [])
def twitter_auth(
    ctx, auth='', denied=False, oauth_token=None, oauth_verifier=None
    ):
    if denied:
        db.delete(create_key('R', denied))
        raise Redirect('/')
    ent = RequestToken.get_by_key_name(oauth_token)
    if not ent:
        raise Redirect('/.twitter.login')
    info = client.get_access_token(oauth_token, ent.s, oauth_verifier)
    ent.delete()
    user = User.get_or_insert(info['user_id'])
    user.s = info['oauth_token_secret']
    user.t = info['oauth_token']
    user.u = info['screen_name']
    user.put()
    ctx.set_secure_cookie('user', "%s|%s" % (info['user_id'], user.u))
    raise Redirect('/')
