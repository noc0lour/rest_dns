#!/usr/bin/env python
import yaml
import argparse
import os

from flask import Flask, request
from flask_jwt import JWT, jwt_required, current_identity

from auth import authenticate, identity, import_users
# from rest_dns.nsupdate import update

app = Flask(__name__)
jwt = JWT(app, authenticate, identity)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file',
                        help='configuration file',
                        default='/etc/rest_dns/config.json')
    parser.add_argument('-n', '--dry-run',
                        help='show changes which will be made',
                        action='store_true')
    return parser.parse_args()


def check_config(config):
    user_config = config.get('users', None)
    if user_config is None:
        return False
    import_users(user_config)
    zone_config = config.get('zones', None)
    if zone_config is None:
        return False
    return True


@app.route('/api/')
def api():
    return "REST DNS API"


@app.route('/api/v1/<zone>/<entry>', methods=['POST'])
@jwt_required()
def zone_access(zone, entry):
    if request.method == 'POST':
        zone_request = request.get_json(force=True)
        if zone_request is None:
            return "", 406
        print(zone_request)
        return "Request successfully processed\n", 201


if __name__ == "__main__":
    args = parse_args()
    try:
        with open(args.file, 'r') as cf:
            config = yaml.safe_load(cf)
    except:
        exit(1)
    if not check_config(config):
        exit(1)
    app.debug = True
    app.config['JWT_SECRET_KEY'] = 'super-secret'.encode('utf-8')
    app.run()
