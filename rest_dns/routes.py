from flask import request
from flask_jwt import jwt_required, current_identity

from .server import app
from .helper import check_request, check_acl, process_request

from ipaddress import ip_address


@app.route('/api/')
def api():
    return "REST DNS API"


@app.route('/api/v1/<zone>/<entry>', methods=['POST'])
@jwt_required()
def zone_access(zone, entry):
    if request.method == 'POST':
        zone_request = request.get_json(force=True)
        zone_acl = app.config.get('zones').get(zone, None)
        if zone_acl is None:
            return "No ACL for zone %s found\n" % zone, 404
        # will alter zone_request (fix types)
        (request_ok, reply) = check_request(zone, entry, zone_request)
        if not request_ok:
            return reply, 400
        if current_identity.username in zone_acl.get('admin_users', ()):
            process_request(zone, entry, zone_request)
            return "Request successfully processed\n", 201
        acls = zone_acl.get('acl')
        for acl in acls:
            if check_acl(acl, entry, current_identity, zone_request):
                if process_request(zone, entry, zone_request, zone_acl):
                    break
                else:
                    return "Syntax Error\n", 400
        else:
            return "Access denied\n", 403
        return "Request successfully processed\n", 201
    else:
        return "Not found", 404

@app.route('/api/v1/dyn/<zone>/<entry>', method=['POST'])
@jwt_required()
def dyn_update(zone, entry):
    if request.method == 'POST':
        zone_request = request.get_json(force=True)
        zone_acl = app.config.get('zones').get(zone, None)
        if zone_acl is None:
            return "No ACL for zone %s found\n" % zone, 404
        ip_addr = ip_address(request.remote_addr)
        if ip_addr.version == 4:
            zone_request["type"] = "A"
        else:
            zone_request["type"] = "AAAA"
        zone_request["target"] = ip_addr.compressed
        (request_ok, reply) = check_request(zone, entry, zone_request)
        if not request_ok:
            return reply, 400
        if current_identity.username in zone_acl.get('admin_users', ()):
            process_request(zone, entry, zone_request)
            return "Request successfully processed\n", 201
        acls = zone_acl.get('acl')
        for acl in acls:
            if check_acl(acl, entry, current_identity, zone_request):
                if process_request(zone, entry, zone_request, zone_acl):
                    break
                else:
                    return "Syntax Error\n", 400
        else:
            return "Access denied\n", 403
        return "Request successfully processed\n", 201

    else:
        return "Not found", 404
