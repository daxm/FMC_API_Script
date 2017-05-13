# This script takes a greenfield FMC and sets it up for the Roadshow #2 Lab.

import fmcapi

# ############################# User Created Variables to be used below functions ############################
# FMC Server Info.
serverIP = '172.16.100.100'
username = 'apiadmin'
password = 'C1sco12345'

# Security Zones.  Must provide: name and mode fields.
securityzones = [
    {
        'name': 'IN', 'desc': 'Inside Security Zone created by API', 'mode': 'ROUTED'
    },
    {
        'name': 'OUT', 'desc': 'Outside Security Zone created by API', 'mode': 'ROUTED'
    },
    {
        'name': 'DMZ', 'desc': 'DMZ Security Zone created by API', 'mode': 'ROUTED'
    },
]

# Network Objects.  Must provide: name and value fields.
networkobjects = [
    {
        'name': 'HQLAN', 'desc': 'Object created by API.', 'value': '172.16.100.0/24'
    },
    {
        'name': 'REMOTE1LAN', 'desc': 'Object created by API.', 'value': '172.16.103.0/24'
    },
    {
        'name': 'FMC_Private', 'desc': 'Object created by API.', 'value': '172.16.100.100'
    },
    {
        'name': 'FMC_Public', 'desc': 'Object created by API.', 'value': '198.18.1.100'
    },
    {
        'name': 'ExampleCorpLANs', 'desc': 'Object created by API.', 'value': '172.16.0.0/16'
    },
    {
        'name': 'HQ_DFGW', 'desc': 'Object created by API.', 'value': '198.18.1.1'
    },
    {
        'name': 'HQ_AD', 'desc': 'Object created by API.', 'value': '172.16.100.102'
    },
    {
        'name': 'HQ_WKST', 'desc': 'Object created by API.', 'value': '172.16.100.250'
    },
]

# Access Control Polices.  Must provide: name, defaultAction.
accesscontrolpolicies = [
    {
        'name': 'Base', 'desc': 'Built by API', 'defaultAction': 'BLOCK'
    },
    {
        'name': 'HQ', 'desc': 'Built by API', 'defaultAction': 'BLOCK', 'parent': 'Base'
    },
    {
        'name': 'Remote Locations', 'desc': 'Built by API', 'defaultAction': 'BLOCK', 'parent': 'Base'
    },
]

# ACP Rules.  Must provide: name, acpName, action,
acprules = [
    {
        'name': 'INET Access',
        'acpName': 'Base',
        'action': 'ALLOW',
        'enabled': 'true',
        'logBegin': 'true',
        'logEnd': 'true',
        'ipsPolicy': 'Security Over Connectivity',
        'sourceZones': [
            {'name': 'IN'},
        ],
        'destinationZones': [
            {'name': 'OUT'},
        ],
        'sourceNetworks': [
            {'name': 'ExampleCorpLANs'},
        ],
        'destinationNetworks': [
            {'name': 'any'},
        ],
    },
]

# ########################################### Main Program ####################################################

with fmcapi.FMC(serverIP, username=username, password=password, autodeploy=False) as fmc1:
    # Create Security Zones
    fmc1.createsecurityzones(securityzones)
    # Create Network Objects
    fmc1.createnetworkobjects(networkobjects)
    # Create Access Control Policies
    fmc1.createacps(accesscontrolpolicies)
    # Create ACP Rules
    fmc1.createacprules(acprules)
