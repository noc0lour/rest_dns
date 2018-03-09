# Wrap REST API around nsupdate

This is a simple python application which uses the Flask framework to expose a REST API to a nsupdate interface. Configuration allows enforcing granular ACLs to subdomains.
This application is meant to be used with Let's Encrypt using the DNS-01 API and acme.sh.

# Dependencies

This application is written in Python3 and not tested with Python 2.x
It might work using Python 2.x, but it is highly unlikely.
 - dnspython
 - flask
 - flask_jwt
 - passlib
