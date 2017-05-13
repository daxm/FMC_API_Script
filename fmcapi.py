import datetime
import json
import requests
import sys
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable annoying HTTP warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

"""
Firepower Management Center API wrapper class for managing Firepower Threat Defense devices.

http://www.cisco.com/c/en/us/td/docs/security/firepower/610/api/REST/Firepower_REST_API_Quick_Start_Guide/Objects_in_the_REST_API.html
"""

class FMC(object):
    """
    FMC objects
    """
    
    API_PLATFORM_VERSION = '/api/fmc_platform/v1/'
    API_CONFIG_VERSION = '/api/fmc_config/v1/'
    VERIFY_CERT = False
    TOKEN_LIFETIME = 60 * 30
    
    def __init__(self, host, username='admin', password='Admin123', autodeploy=True):
        self.host = host
        self.username = username
        self.password = password
        self.autodeploy = autodeploy

    def __enter__(self):
        self.connect()
        return self
        
    def __exit__(self, *args):
        if self.autodeploy:
            self.deploychanges()
        else:
            print("Auto deploy changes set to False.  Use the Deploy button in FMC to push changes to FTDs.")

    def reset_token_expiry(self):
        self.token_expiry = datetime.datetime.now() + datetime.timedelta(seconds=self.TOKEN_LIFETIME)

    def refresh_token(self):
        self.headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.token, 'X-auth-refresh-token': self.refreshtoken }
        self.url = "https://" + self.host + self.API_PLATFORM_VERSION + "auth/refreshtoken"
        print("Refreshing token from %s." % self.url)
        response = requests.post(self.url, headers=self.headers, verify=self.VERIFY_CERT)
        self.token_refreshes += 1
        self.reset_token_expiry()
        self.token = self.headers.get('X-auth-access-token')
        self.refreshtoken = self.headers.get('X-auth-refresh-token')
        self.headers['X-auth-access-token'] = self.token
        
    def connect(self):
        # define fuction to connect to the FMC API and generate authentication token
        # Token is good for 30 minutes.
        self.headers = {'Content-Type': 'application/json'}
        self.url = "https://" + self.host + self.API_PLATFORM_VERSION + "auth/generatetoken"
        print("Requesting token from %s." % self.url)
        self.response = requests.post(self.url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=self.VERIFY_CERT)
        self.token = self.response.headers.get('X-auth-access-token')
        self.refreshtoken = self.response.headers.get('X-auth-refresh-token')
        self.uuid = self.response.headers.get('DOMAIN_UUID')
        if self.token is None or self.uuid is None:
            print("No Token or DOMAIN_UUID found, terminating....")
            sys.exit()
            
        self.base_url = "https://" + self.host + self.API_CONFIG_VERSION + "domain/" + self.uuid
        self.reset_token_expiry()
        self.token_refreshes = 0
            
        print("Token creation a success -->", self.token, "which expires ", self.token_expiry)

    def checktoken(self):
        if datetime.datetime.now() > self.token_expiry:
            print("Token Expired.  Generating new token.")
            self.connect()

    def postdata(self, url, json_data):
        self.checktoken()
        # POST json_data with the REST CALL
        try:
            headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.token}
            url = self.base_url + url
            response = requests.post(url, json=json_data, headers=headers, verify=self.VERIFY_CERT)
            status_code = response.status_code
            json_response = json.loads(response.text)
            if status_code > 301 or 'error' in json_response:
                response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("Error in POST operation -->", str(err))
            print("json_response -->\t", json_response)
        if response:
            response.close()
        return json_response

    def putdata(self, url, json_data):
        self.checktoken()
        # PUT json_data with the REST CALL
        try:
            headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.token}
            url = self.base_url + url
            response = requests.put(url, json=json_data, headers=headers, verify=self.VERIFY_CERT)
            status_code = response.status_code
            json_response = json.loads(response.text)
            if status_code > 301 or 'error' in json_response:
                response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("Error in PUT operation -->", str(err))
            print("json_response -->\t", json_response)
        if response:
            response.close()
        return json_response

    def getdata(self, url):
        self.checktoken()
        # GET requested data and return it.
        try:
            headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.token}
            url = self.base_url + url
            response = requests.get(url, headers=headers, verify=self.VERIFY_CERT)
            status_code = response.status_code
            json_response = json.loads(response.text)
            if status_code > 301 or 'error' in json_response:
                response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("Error in GET operation -->", str(err))
            print("json_response -->\t", json_response)
        if response:
            response.close()
        return json_response

    def getdeployabledevices(self):
        waittime = 15
        print("Waiting %s seconds to allow the FMC to update the list of deployable devices." % waittime)
        time.sleep(waittime)
        print("Getting a list of deployable devices.")
        url = "/deployment/deployabledevices?expanded=true"
        response = self.getdata(url)
        # Now to parse the response list to get the UUIDs of each device.
        if 'items' not in response:
            return
        uuids = []
        for item in response['items']:
            if not item['canBeDeployed']:
                pass
            else:
                uuids.append(item['device']['id'])
        return uuids

    def deploychanges(self):
        url = "/deployment/deploymentrequests"
        devices = self.getdeployabledevices()
        if not devices:
            print("No devices need deployed.")
            return
        nowtime = int(1000 * datetime.datetime.now().timestamp())
        json_data = {
            'type': 'DeploymentRequest',
            'forceDeploy': True,
            'ignoreWarning': True,
            'version': nowtime,
            'deviceList': []
        }
        for device in devices:
            print("Adding device %s to deployment queue." % device)
            json_data['deviceList'].append(device)
        print("Deploying changes to devices.")
        response = self.postdata(url, json_data)
        return response['deviceList']

    def createsecurityzones(self, zones):
        print("Creating Security Zones.")
        url = "/object/securityzones"
        for zone in zones:
            json_data = {
                "type": "SecurityZone",
                "name": zone['name'],
                "description": zone['desc'],
                "interfaceMode": zone['mode'],
            }
            response = self.postdata(url, json_data)
            if response.get('id', '') is not '':
                zone['id'] = response['id']
                print("\tSecurity Zone", zone['name'], "created.")

    def createnetworkobjects(self, objects):
        print("Creating Network Objects.")
        url = "/object/networks"
        for obj in objects:
            json_data = {
                'name': obj['name'],
                'value': obj['value'],
                'description': obj['desc'],
                'type': 'Network',
            }
            response = self.postdata(url, json_data)
            if response.get('id', '') is not '':
                obj['id'] = response['id']
                print("\tNetwork Object", obj['name'], "created.")

    def createurls(self, objects):
        print("Creating URL Objects.")
        url = "/object/urls"
        for obj in objects:
            json_data = {
                'name': obj['name'],
                'url': obj['value'],
                'description': obj['desc'],
                'type': 'Url',
            }
            response = self.postdata(url, json_data)
            if response.get('id', '') is not '':
                obj['id'] = response['id']
                print("\tURL Object", obj['name'], "created.")

    def createacps(self, policies):
        print("Creating Access Control Policies.")
        url = "/policy/accesspolicies"
        for policy in policies:
            json_data = {
                'type': "AccessPolicy",
                'name': policy['name'],
                'description': policy['desc'],
            }
            if False and policy.get('parent', '') is not '':
                # Modifying Metatdata is not supported so we cannot create "child" ACPs yet.  :-(
                url_search = url + "?name=" + policy['parent']
                response = self.getdata(url_search)
                json_data['metadata'] = {
                    'inherit': True,
                    'parentPolicy': {
                        'type': 'AccessPolicy',
                        'name': policy['parent'],
                        'id': response['items'][0]['id']
                    }
                }
            else:
                json_data['defaultAction'] = {'action': policy['defaultAction']}
            response = self.postdata(url, json_data)
            if response.get('id', '') is not '':
                policy['id'] = response['id']
                print("\tAccess Control Policy", policy['name'], "created.")

    def createacprules(self, rules):
        print("Creating ACP Rules.")
        for rule in rules:
            # Get ACP's ID for this rule
            url_search = "/policy/accesspolicies" + "?name=" + rule['acpName']
            response = self.getdata(url_search)
            acp_id = None
            if response.get('items', '') is '':
                print("Access Control Policy not found. Exiting.")
                continue
            else:
                acp_id = response['items'][0]['id']
            # NOTE: This json_data is written specific to match what I'm setting from the acpRuleList.
            # It will need to be updated if/when I create more advanced ACP Rules.
            json_data = {
                'name': rule['name'],
                'action': rule['action'],
                'type': 'AccessRule',
                'enabled': rule['enabled'],
                'sendEventsToFMC': True,
                'logBegin': rule['logBegin'],
                'logEnd': rule['logEnd'],
            }
            if rule.get('ipsPolicy', '') is not '':
                # Currently you cannot query IPS Policies by name.  I'll have to grab them all and filter from there.
                url_search = "/policy/intrusionpolicies"
                response = self.getdata(url_search)
                ips_policy_id = None
                for policy in response['items']:
                    if policy['name'] == rule['ipsPolicy']:
                        ips_policy_id = policy['id']
                if ips_policy_id is None:
                    print("IPS Policy selected for this rule is not found.  Skipping IPS Policy assignment.")
                else:
                    json_data['ipsPolicy'] = {
                        'name': rule['ipsPolicy'],
                        'id': ips_policy_id,
                        'type': 'IntrusionPolicy'
                    }
            if rule.get('sourceZones', '') is not '':
                # NOTE: There can be more than one sourceZone so we need to account for them all.
                securityzone_ids = []
                for zone in rule['sourceZones']:
                    url_search = "/object/securityzones" + "?name=" + zone['name']
                    response = self.getdata(url_search)
                    if response.get('items', '') is '':
                        print("Security Zone", zone['name'], "is not found.  Skipping this zone.")
                    else:
                        tmp = {
                            'name': zone['name'],
                            'id': response['items'][0]['id'],
                            'type': 'SecurityZone'
                        }
                        securityzone_ids.append(tmp)
                if len(securityzone_ids) > 0:
                    json_data['sourceZones'] = {
                        'objects': securityzone_ids
                    }
            if rule.get('destinationZones', '') is not '':
                # NOTE: There can be more than one destinationZone so we need to account for them all.
                securityzone_ids = []
                for zone in rule['destinationZones']:
                    url_search = "/object/securityzones" + "?name=" + zone['name']
                    response = self.getdata(url_search)
                    if response.get('items', '') is '':
                        print("Security Zone", zone['name'], "is not found.  Skipping this zone.")
                    else:
                        tmp = {
                            'name': zone['name'],
                            'id': response['items'][0]['id'],
                            'type': 'SecurityZone'
                        }
                        securityzone_ids.append(tmp)
                if len(securityzone_ids) > 0:
                    json_data['destinationZones'] = {
                        'objects': securityzone_ids
                    }
            if rule.get('sourceNetworks', '') is not '':
                # Currently you cannot query Network Objects by name.  I'll have to grab them all and filter from there.
                url_search = "/object/networks"
                # Grab a copy of the current Network Objects on the server and we will cycle through these for each
                # sourceNetwork.
                respone_network_obj = self.getdata(url_search)
                network_obj_ids = []
                for network in rule['sourceNetworks']:
                    testvar = False
                    for obj in respone_network_obj['items']:
                        if network['name'] == obj['name']:
                            tmp = {
                                'type': 'Network',
                                'name': obj['name'],
                                'id': obj['id']
                            }
                            network_obj_ids.append(tmp)
                            testvar = True
                    if testvar is False:
                        print("Network", network['name'], "was not found.  Skipping it.")
                if len(network_obj_ids) < 1:
                    print("No sourceNetworks.  Skipping this section.")
                else:
                    json_data['sourceNetworks'] = {
                        'objects': network_obj_ids
                    }
            if rule.get('destinationNetworks', '') is not '':
                # Currently you cannot query Network Objects by name.  I'll have to grab them all and filter from there.
                url_search = "/object/networks"
                # Grab a copy of the current Network Objects on the server and we will cycle through these for each
                # sourceNetwork.
                respone_network_obj = self.getdata(url_search)
                network_obj_ids = []
                for network in rule['destinationNetworks']:
                    testvar = False
                    for obj in respone_network_obj['items']:
                        if network['name'] == obj['name']:
                            tmp = {
                                'type': 'Network',
                                'name': obj['name'],
                                'id': obj['id']
                            }
                            network_obj_ids.append(tmp)
                            testvar = True
                    if testvar is False:
                        print("Network", network['name'], "was not found.  Skipping it.")
                if len(network_obj_ids) < 1:
                    print("No destinationNetworks.  Skipping this section.")
                else:
                    json_data['destinationNetworks'] = {
                        'objects': network_obj_ids
                    }
            # Update URL to be specific to this ACP's ruleset.
            url = "/policy/accesspolicies/" + acp_id + "/accessrules"
            response = self.postdata(url, json_data)
            if response.get('id', '') is not '':
                rule['id'] = response['id']
                print("\tACP Rule", rule['name'], "created.")

    def registerdevices(self, devices):
        print("Registering FTD Devices.")
        for device in devices:
            json_data = {
                'type': 'Device',
                'name': device['name'],
                'hostName': device['hostName'],
                'regKey': device['regkey'],
                'version': device['version'],
                'license_caps': device['licenses'],
            }
            # Get ACP's ID for this rule
            url_search = "/policy/accesspolicies" + "?name=" + device['acpName']
            response = self.getdata(url_search)
            if response.get('items', '') is '':
                print("Access Control Policy not found. Exiting.")
                continue
            json_data['accessPolicy'] = {
                'name': device['acpName'],
                'id': response['items'][0]['id'],
                'type': 'AccessPolicy'
            }
            url = "/devices/devicerecords"
            response = self.postdata(url, json_data)
            if response.get('metadata', '') is not '':
                print("\tDevice registration can take some time (5 minutes or more).")
                print("\t\tIssue the command 'show managers' on", device['name'], "to view progress.")

    def modifydevice_physicalinterfaces(self, device_attributes):
        print("Modifying Physical Interfaces on FTD Devices.")
        # Get ID of this FTD Device first.  Alas, you can't GET by name.  :-(
        url_search = "/devices/devicerecords"
        # Grab a copy of the current Devices on the server so that we can cycle through to find the one we want.
        response_devices = self.getdata(url_search)
        if response_devices.get('items', '') is '':
            # It there are no devices (or we can't query them for some reason) none of this will work.
            print("Query for a list of Devices failed.  Exiting.")
            return
        for attribute in device_attributes:
            # Find the Device ID for this set of interfaces.
            device_id = None
            for device in response_devices['items']:
                if device['name'] == attribute['deviceName']:
                    device_id = device['id']
            if device_id is None:
                print("Device", attribute['deviceName'], "is not found.  Skipping modifying interfaces.")
            else:
                #  Now that we have the device's ID.  Time to loop through our physical interfaces and see if we can
                # match them to this device's interfaces to get an ID.
                for device in attribute['physicalInterfaces']:
                    url = url_search + "/" + device_id + "/physicalinterfaces"
                    url_search2 = url + "?name=" + device['name']
                    response_interface = self.getdata(url_search2)
                    if response_interface.get('items', '') is '':
                        print("For device", attribute['deviceName'],
                              "there is no physical interface named", device['name'])
                    else:
                        # Get the ID for the Security Zone.
                        url_search3 = "/object/securityzones" + "?name=" + device['securityZone']
                        response_securityzone = self.getdata(url_search3)
                        if response_securityzone.get('items', '') is '':
                            print("Security Zone", device['securityZone'], "is not found."
                                                                           "Skipping modifying interface",
                                  device['name'], "for device", attribute['deviceName'])
                        else:
                            # Time to modify this interface's information.
                            json_data = {
                                'type': 'PhysicalInterface',
                                'enabled': True,
                                'name': device['name'],
                                'id': response_interface['items'][0]['id'],
                                'ifname': device['ifName'],
                                'securityZone': {
                                    'id': response_securityzone['items'][0]['id'],
                                    'name': device['securityZone'],
                                    'type': 'SecurityZone'
                                },
                                'ipv4': device['ipv4'],
                            }
                    response = self.putdata(url, json_data)
                    if response.get('metadata', '') is not '':
                        print("\tInterface", device['name'], "on device", attribute['deviceName'], "has been modified.")
                    else:
                        print("\tSomething wrong happened when modifying interface", device['name'], "on device", attribute['deviceName'])
