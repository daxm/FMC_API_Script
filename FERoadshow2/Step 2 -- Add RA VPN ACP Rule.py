import fmcapi

# ############################# User Created Variables to be used below functions ############################
# FMC Server Info.
serverIP = '172.16.100.100'
username = 'apiadmin'
password = 'C1sco12345'

# ACP Rules.  Must provide: name, acpName, action,
acprules = [
    {
        'name': 'RA VPN',
        'acpName': 'HQ',
        'action': 'ALLOW',
        'enabled': True,
        'logBegin': True,
        'logEnd': True,
        'ipsPolicy': 'Security Over Connectivity',
        'sourceZones': [
            {'name': 'OUT'},
        ],
        'destinationZones': [
            {'name': 'IN'},
        ],
        'sourceNetworks': [
            {'name': 'HQ_VPNLAN'},
        ],
        'destinationNetworks': [
            {'name': 'HQLAN'},
        ],
    },
]

# ########################################### Main Program ####################################################

with fmcapi.FMC(serverIP, username=username, password=password) as fmc1:
    # Create ACP Rules
    fmc1.createacprules(acprules)
