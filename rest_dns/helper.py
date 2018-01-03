import argparse
import re

from dns import update
from dns import tsigkeyring
from dns import query
from dns import rdataset
from dns import tsig

valid_request_fields = {
    "request_type": ("add", "del"),
    "class": ("IN"),
    "ttl": int,
    "type": ("A", "AAAA", "CNAME", "TXT", "MX", "NS", "PTR", "SOA"),
    "target": str,
}


def parse_args():
    """
    Parse arguments 
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file',
                        help='configuration file',
                        default='/etc/rest_dns/config.json')
    parser.add_argument('-n', '--dry-run',
                        help='show changes which will be made',
                        action='store_true')
    return parser.parse_args()


def check_config(app, config):
    if config.get('debug', None) is not None:
        app.debug = True
    user_config = config.get('users', None)
    if user_config is None:
        return False
    zone_config = config.get('zones', None)
    if zone_config is None:
        return False
    if re.match('change_me', config.get('JWT_SECRET_KEY'), re.I):
        app.logger.error('Set the value of JWT_SECRET_KEY in production configuration!')
    return True


def default_config():
    config = {
        'debug': False,
        'JWT_SECRET_KEY': 'CHANGE_ME',
    }
    return config

def check_request(zone, entry, request):
    """
    check request dict if all necessary fields are
    present and kinda valid
    """
    mandatory_keys = ("request_type", "type")
    if not set.issubset(set(mandatory_keys), set(request.keys())):
        return (False, "Mandatory key(s) %s missing in request\n" %
                set.difference(set(mandatory_keys), set(request.keys())))

    for key, value in request.items():
        valid_value = valid_request_fields.get(key, None)
        if valid_value is None:
            return (False, "Key %s is not allowed in request\n" % key)
        if type(valid_value) == type:
            try:
                request[key] = valid_value(value)
            except Exception:
                return (False, "Value %s is not allowed for key %s. Must be of type %s\n"
                        % (value, key, valid_value))
        else:
            if value not in valid_value:
                return (False, "Value %s is not allowed for key %s. Must be one of %s\n"
                        % (value, key, valid_value))

    return (True, request)

def check_acl(acl, entry, identity, request):
    for s in acl.get("subdomains"):
        if re.match(s, entry):
            break
    else:
        return False
    if identity.username not in acl.get("users", ()):
        return False
    if ("w" not in acl.get("access")) and (request.get("request_type") in ["add", "del"]):
        return False
    if ("r" not in acl.get("access")) and (request.get("request_type") in ["show"]):
        return False
    if request.get("type") not in acl.get("record_types"):
        return False
    return True


def process_request(zone, entry, request, zone_acl):
    # request is already checked and acl is applied
    keyring = None
    if not zone_acl.get("master_auth", "none").lower() == "none":
        keyfile = zone_acl.get("master_auth_key", None)
        if keyfile is None:
            return False
        with open(keyfile, 'rt') as f:
            key = f.read().rstrip()
        keyring = tsigkeyring.from_text({
            "test.key": key
        })
    if keyring is not None:
        zone_update = update.Update(zone, keyring=keyring, keyalgorithm=tsig.HMAC_SHA512)
    else:
        zone_update = update.Update(zone)
    zone_data = rdataset.from_text(request.get("class", "IN"), request.get("type"), request.get("ttl", None), request.get("target", ""))
    if request.get("request_type") == "add":
        zone_update.add(entry, zone_data)
    elif request.get("request_type") == "del":
        zone_update.delete(entry, zone_data)
        print(zone_update.to_text)
    try:
        query.tcp(zone_update, zone_acl.get("master"))
    except Exception as e:
        return False
    return True
