# Expose REST API to knot authorative DNS 

This is a simple python application which uses the Flask framework to expose a REST API to a nsupdate interface. Configuration allows enforcing granular ACLs to subdomains. 
This application is meant to be used with Let's Encrypt using the DNS-01 API and acme.sh.
