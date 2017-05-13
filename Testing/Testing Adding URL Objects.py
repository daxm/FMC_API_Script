import fmcapi

# ############################# User Created Variables to be used below functions ############################
# FMC Server Info.
serverIP = '172.16.100.100'
username = 'apiadmin'
password = 'C1sco12345'


# Network Objects.  Must provide: name and value fields.  Can't have spaces in Name!!!
urlobjects = [
    {
        'name': 'daxm_TLD', 'desc': 'Object created by API.', 'value': 'http://www.daxm.net'
    },
    {
        'name': 'Cisco_Downloads', 'desc': 'Object created by API.', 'value': 'cisco.com/downloads'
    },
    {
        'name': 'CNN_TLD', 'desc': 'Object created by API.', 'value': 'cnn.com'
    },
    {
        'name': 'FOXNEWS_Website', 'desc': 'Object created by API.', 'value': 'http://www.foxnews.com'
    },
    {
        'name': 'BBC_File', 'desc': 'Object created by API.', 'value': 'www.bbc.co.uk/image.php'
    },
]

# ########################################### Main Program ####################################################
with fmcapi.FMC(serverIP, username, password) as fmc1:
    # Add URL Objects to FMC
    fmc1.createurls(urlobjects)

