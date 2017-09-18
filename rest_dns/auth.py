from werkzeug.security import safe_str_cmp
from passlib.hash import pbkdf2_sha512

users = []
username_table = {}
userid_table = {}

class User(object):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.id

def import_users(cf_users):
    for num, user in enumerate(cf_users, 1):
        users.append(User(num, user.get('name'), user.get('password').encode('utf-8')))
    username_table.update({user.username: user for user in users})
    userid_table.update({user.id: user for user in users})

def authenticate(username, password):
    user = username_table.get(username, None)
    if user and pbkdf2_sha512.verify(password.encode('utf-8'), user.password):
        return user
    return None

def identity(payload):
    user_id = payload['identity']
    return userid_table.get(user_id, None)
