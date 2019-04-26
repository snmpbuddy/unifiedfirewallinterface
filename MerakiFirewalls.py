import json

import requests

from Firewall import *


class MerakiRequest():
    def __init__(self, apiKey):
        self.base_url = 'https://api.meraki.com/api/v0'
        self.apiKey = apiKey

    def meraki_get(self, url):
        geturl = ('{0}/' + url).format(self.base_url)
        headers = {
            'X-Cisco-Meraki-API-Key': format(str(self.apiKey)),
            'Content-Type': 'application/json'
        }
        response = requests.get(geturl, headers=headers)
        if str(response.status_code).startswith("2"):
            return True, response.json()
        else:
            return False, {"error_code": response.status_code, "error_message": str(response.content)}

    def meraki_put(self, url, data):
        puturl = ('{0}/' + url).format(self.base_url)
        headers = {
            'x-cisco-meraki-api-key': format(self.apiKey),
            'Content-Type': 'application/json'
        }
        response = requests.put(puturl, json.dumps(data), headers=headers)
        if str(response.status_code).startswith("2"):
            return True, response.json()
        else:
            return False, {"error_code": response.status_code, "error_message": str(response.content)}


class MerakiContext(FirewallContext):
    def __init__(self, apikey):
        super().__init__()
        self.meraki_request = MerakiRequest(apikey)
        self.apikey = apikey

    def get_organizations(self):
        return self.meraki_request.meraki_get("organizations")

    def get_networks(self, orgid):
        return self.meraki_request.meraki_get("organizations/{0}/networks".format(orgid))

    def get_SSID_for_network(self, networkid):
        return self.meraki_request.meraki_get("networks/{0}/ssids".format(networkid))


class MerakiMXFirewall(L3Firewall):
    def __init__(self):
        super().__init__()
        self.model = "Meraki-MX"

    def get_authentication_parameters(self):
        return ["dashboardapikey"]

    def get_context(self, authentication_params):
        return MerakiContext(authentication_params["dashboardapikey"])

    def load_rules(self, context):
        if "network_id" not in context.context_map:
            return False, {"error_code": 0,
                           "error_message": "Require one or more Network IDs to be set to get firewall rules"}
        else:
            status, mxrules = context.meraki_request.meraki_get(
                "networks/{0}/l3FirewallRules".format(context.context_map["network_id"]))
            if status:
                fwrules = []
                for rule in mxrules:
                    fwrule = L3FirewallRule()
                    fwrule.destination = rule["destCidr"]
                    fwrule.destination_port = rule["destPort"]
                    fwrule.source = rule["srcCidr"]
                    fwrule.source_port = rule["srcPort"]
                    fwrule.protocol = rule["protocol"]
                    fwrule.policy = rule["policy"].lower()
                    fwrule.comment = rule["comment"]
                    fwrules.append(fwrule)
                self.l3rules = fwrules

    def apply_rules(self, rules, context):
        if "network_id" not in context.context_map:
            return False, "Require one or more Network IDs to be set to update firewall rules"
        else:
            mxrules = []
            for fwrule in rules:
                if fwrule.comment == "Default rule":
                    continue
                rule = dict()
                rule["destCidr"] = fwrule.destination
                rule["destPort"] = fwrule.destination_port
                rule["srcCidr"] = fwrule.source
                rule["srcPort"] = fwrule.source_port
                rule["protocol"] = fwrule.protocol
                rule["policy"] = fwrule.policy
                rule["comment"] = fwrule.comment
                mxrules.append(rule)
            status, response = context.meraki_request.meraki_put(
                "networks/{0}/l3FirewallRules".format(context.context_map["network_id"]), {"rules": mxrules})
            print(response)
            return status, response


class MerakiSSIDFirewall(L3Firewall):
    def __init__(self):
        super().__init__()
        self.model = "Meraki-SSID"

    def get_authentication_parameters(self):
        return ["dashboardapikey"]

    def get_context(self, authentication_params):
        return MerakiContext(authentication_params["dashboardapikey"])

    def load_rules(self, context):
        if "network_id" not in context.context_map:
            return False, "Require one or more Network IDs to be set to get firewall rules"
        if "ssid_number" not in context.context_map:
            return False, "Require one or more SSID Numbers to be set to get firewall rules for SSID"
        status, ssidrules = context.meraki_request.meraki_get(
            "networks/{0}/ssids/{1}/l3FirewallRules".format(context.context_map["network_id"],
                                                            context.context_map["ssid_number"]))
        fwrules = []
        for rule in ssidrules:
            fwrule = L3FirewallRule()
            fwrule.destination = rule["destCidr"]
            fwrule.destinationPort = rule["destPort"]

            fwrule.protocol = rule["protocol"]
            fwrule.policy = rule["policy"].lower()
            fwrules.append(fwrule)
        return True, fwrules

    def apply_rules(self, rules, context):
        if "network_id" not in context.context_map:
            return False, "Require one or more Network IDs to be set to update firewall rules"
        if "ssid_number" not in context.context_map:
            return False, "Require one or more SSID Numbers to be set to get firewall rules for SSID"
        mrrules = []
        for fwrule in rules:
            rule = dict()
            rule["destCidr"] = fwrule.destination
            rule["destPort"] = fwrule.destinationPort
            rule["protocol"] = fwrule.protocol
            rule["policy"] = fwrule.policy
            mrrules.append(fwrule)
        status, mr_rules = context.meraki_request.meraki_put(
            "networks/{0}/ssids/{1}/l3FirewallRules".format(context.context_map["network_id"],
                                                            context.context_map["ssid_number"], {"rules": mrrules}))


class MerakiSiteToSiteVPNFirewall(L3Firewall):
    def __init__(self):
        super().__init__()
        self.model = "Meraki-SiteToSiteVPN"

    def get_authentication_parameters(self):
        return ["dashboardapikey"]

    def get_context(self, authentication_params):
        return MerakiContext(authentication_params["dashboardapikey"])

    def load_rules(self, context):
        if "organization_id" not in context.context_map:
            return False, "Require one or more Organization IDs to be set to get firewall rules"

        status, vpnrules = context.meraki_request.meraki_get(
            "organizations/{0}/vpnFirewallRules".format(context.context_map["organization_id"]))
        fwrules = []
        for rule in vpnrules:
            fwrule = L3FirewallRule()
            fwrule.destination = rule["destCidr"]
            fwrule.destinationPort = rule["destPort"]
            fwrule.sourcePort = rule["srcPort"]
            fwrule.source = rule["srcCidr"]
            fwrule.protocol = rule["protocol"]
            fwrule.policy = rule["policy"].lower()
            fwrules.append(fwrule)
        return True, fwrules

    def apply_rules(self, rules, context):
        """
        :type rules: L3FirewallRule
        :type context: MerakiContext
        """
        mxvpnrules = []
        for fwrule in rules:
            rule = dict()
            rule["destCidr"] = fwrule.destination
            rule["destPort"] = fwrule.destinationPort
            rule["srcCidr"] = fwrule.source
            rule["srcPort"] = fwrule.sourcePort
            rule["protocol"] = fwrule.protocol
            rule["policy"] = fwrule.policy
            mxvpnrules.append(fwrule)
        update_ret = context.meraki_request.meraki_put(
            "organizations/{0}/vpnFirewallRules".format(context.context_map["organization_id"]),
            {"rules": mxvpnrules})
        if isinstance(update_ret, str):
            return False, update_ret
        else:
            return True, update_ret
