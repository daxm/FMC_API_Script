
import fmcapi

# ############################# User Created Variables to be used below functions ############################
# FMC Server Info.
serverIP = '172.16.100.100'
username = 'apiadmin'
password = 'C1sco12345'

# FTD Devices.  Must provide: hostName, acpName, regkey
devices = [
    {
        'name': 'ftd3', 'hostName': '172.16.100.12', 'acpName': 'HQ', 'regkey': 'cisco123', 'version': '6.2.1',
        'licenses': ['BASE', 'PROTECT', 'MALWARE', 'URLFilter', 'CONTROL', 'VPN'],
    },
]

# FTD Device Attributes.
deviceattributes = [
    {
        'deviceName': 'FTD3',
        'physicalInterfaces':
            [
                {
                    'ipv4': {
                        'static': {
                            'address': '172.16.100.4',
                            'netmask': '24',
                        },
                    },
                    'ifName': 'LAN',
                    'securityZone': 'IN',
                    'name': 'GigabitEthernet0/0',
                },
                {
                    'ipv4': {
                        'static': {
                            'address': '198.18.1.4',
                            'netmask': '24',
                        },
                    },
                    'ifName': 'ISP',
                    'securityZone': 'OUT',
                    'name': 'GigabitEthernet0/1',
                },
            ],
    },
]

# ########################################### Main Program ####################################################
with fmcapi.FMC(serverIP, username=username, password=password, autodeploy=False) as fmc1:
    # Add FTD devices to FMC
    fmc1.registerdevices(devices)

    # Modify FTD devices
    # DOESN'T WORK YET
    # fmc1.modifydevice_physicalinterfaces(deviceattributes)
