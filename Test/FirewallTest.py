import MerakiFirewalls

if __name__ == "__main__":
    apiKey = "YOUR API KEY HERE"
    context = MerakiFirewalls.MerakiContext(apiKey)
    status, orgs = context.get_organizations()
    if status:
        status, networks = context.get_networks(orgs[0]['id'])
        context.context_map["network_id"] = networks[0]['id']
        status, ssids = context.get_SSID_for_network(networks[0]["id"])
        print(ssids)
        '''
        status,l3rules=MerakiMXFirewall(context).get_firewall_rules(context)
        rule=copy.deepcopy(l3rules[0])
        rule.destination="192.168.31.0"
        rule.destination_port=443
        l3rules.append(rule)
        #rules=[rule]
        status, l3rules = MerakiMXFirewall(context).set_firewall_rules(l3rules,context)
        print("Apply status"+str(status)+str(l3rules))
        status, l3rules = MerakiMXFirewall(context).get_firewall_rules(context)
        print(l3rules)
        '''
