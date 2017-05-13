# This script takes a greenfield FMC and sets it up for the Roadshow #2 Lab.

import fmcapi

# ############################# User Created Variables to be used below functions ############################
# FMC Server Info.
serverIP = '172.16.100.100'
username = 'apiadmin'
password = 'C1sco12345'

# ACP Rules.  Must provide: name, acpName, action,
acprules = [
    {
        'name': 'Remote1 VPN',
        'acpName': 'HQ',
        'action': 'ALLOW',
        'enabled': True,
        'logBegin': True,
        'logEnd': True,
        'ipsPolicy': 'Security Over Connectivity',
        'sourceZones': [
            {'name': 'IN'},
        ],
        'destinationZones': [
            {'name': 'OUT'},
        ],
        'sourceNetworks': [
            {'name': 'HQLAN'},
        ],
        'destinationNetworks': [
            {'name': 'REMOTE1LAN'},
        ],
    },
]

# ########################################### Main Program ####################################################

with fmcapi.FMC(serverIP, username=username, password=password) as fmc1:
    # Create ACP Rules
    fmc1.createacprules(acprules)
