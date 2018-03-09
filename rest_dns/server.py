#!/usr/bin/env python
import yaml
from os import environ

from flask import Flask
from flask_jwt import JWT

from .helper import parse_args, check_config, default_config
from .auth import authenticate, identity, import_users
# from rest_dns.nsupdate import update

app = Flask(__name__)
jwt = JWT(app, authenticate, identity)

app.config.update(default_config())


def main_cfg():
    args = parse_args()
    try:
        with open(args.file, 'r') as cf:
            config = yaml.safe_load(cf)
    except:
        exit(1)
    return config


def env_cfg():
    env_var = environ.get('REST_DNS_CFG', None)
    if env_var is not None:
        try:
            with open(env_var, 'r') as cf:
                config = yaml.safe_load(cf)
        except:
            print("Failed opening configuration!")
            exit(1)
        return config
    return {}


if __name__ == '__main__':
    app.config.update(main_cfg())
app.config.update(env_cfg())

if not check_config(app, app.config):
    print('config is wrong')
    exit(1)
import_users(app.config.get('users', None))

from . import routes
