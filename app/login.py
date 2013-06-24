# Public Domain (-) 2013 The Campaign Tweets Authors.
# See the Campaign Tweets UNLICENSE file for details.

from md5 import md5
from urllib import urlencode

from google.appengine.ext import db
from config import SITE_ADMINS

# ------------------------------------------------------------------------------
# Context Extensions
# ------------------------------------------------------------------------------

def get_admin_status(ctx):
    user = ctx.username
    if user and user in SITE_ADMINS:
        return 1

def get_current_user(ctx):
    info = ctx.get_secure_cookie('user')
    if info:
        return info.split('|')[0]

def get_username(ctx):
    info = ctx.get_secure_cookie('user')
    if info:
        return info.split('|')[1]
