class FirewallFactory:
    """
    This class is used to get the corresponding class that represents a specific implementation for a Firewall.
    There are two classes of firewalls a Network layer firewall that works at the port and protocol level and the other
    one which works on application traffic layer such as URL filtering. If the model is registered then an object will be
    returned.
    """

    def __init__(self):
        self.firewalls = {"Meraki-MX": "MerakiMXFirewall", "Meraki-SSID": "MerakiSSIDFirewall",
                          "Meraki-SiteToSiteVPN": "MerakiSiteToSiteVPNFirewall"}

    def get_l3_firewall(self, model):
        firewallImpl = self.firewalls.get(model, None)
        if firewallImpl:
            eval(firewallImpl + "(" + ")")

    def get_l7_firewall(self, model):
        pass


class FirewallContext:
    def __init__(self):
        self.context_map = dict()
        self.context_keys = []

    def add_to_context(self, key, value):
        self.context_map[key] = value
        self.context_keys.append(key)


class L3Firewall:
    def __init__(self):
        self.l3rules = []
        self.model = ""

    def get_model(self):
        return self.model

    def get_firewall_rules(self, context):
        try:
            self.load_rules(context)
        except Exception as e:
            return False, str(e)
        return True, self.l3rules

    def set_firewall_rules(self, rules, context):
        try:
            self.apply_rules(rules, context)
        except Exception as e:
            return False, str(e)
        self.load_rules(context)
        return True, self.l3rules

    def get_authentication_parameters(self):
        pass

    def load_rules(self, context):
        pass

    def apply_rules(self, rules, context):
        pass


class L3FirewallRule:
    def __init__(self):
        self.source = "Any"
        self.source_port = "Any"
        self.destination = "Any"
        self.destination_port = "Any"
        self.protocol = "TCP"  # Allowed values are TCP,UDP
        self.policy = "Deny"  # Allowed values are Allow and Deny
        self.comment = ""

    def __repr__(self):
        return "Source:{0},SourcePort:{0},Destination:{1},DestinationPort:{2},Protocol:{3}, action:{4}".format(
            self.source, self.source_port, self.destination, self.destination_port, self.protocol, self.policy)


class L7FirewallRule:
    def __init__(self):
        self.blockedUrl = ""
        self.allowedUrl = ""
