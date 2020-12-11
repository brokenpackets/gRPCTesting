from cloudvision.Connector.grpc_client import GRPCClient, create_query
from cloudvision.Connector.codec import Wildcard, Path, FrozenDict
import requests
import ssl
import json
import tempfile

cvp_servers = ['cvp.tgconrad.com']
cvp_user = 'admin'
cvp_pass = 'Arista123'
tokenFile = 'token.txt'
certFile = 'cert.crt'

def login(url_prefix, username, password):
    connect_timeout = 10
    headers = {"Accept": "application/json",
           "Content-Type": "application/json"}
    session = requests.Session()
    authdata = {"userId": username, "password": password}
    response = session.post('https://'+url_prefix+'/web/login/authenticate.do', data=json.dumps(authdata),
                            headers=headers, timeout=connect_timeout,
                            verify=False)
    if response.json()['sessionId']:
        token = response.json()['sessionId']
        sslcert = ssl.get_server_certificate((url_prefix,8443))
        return [token,sslcert]

def pretty_print(dataDict):
    def default(obj):
        if isinstance(obj, Path):
            return obj._keys
        if isinstance(obj, (FrozenDict, dict)):
            return obj._dict
    print(json.dumps(
        dataDict, default=default, indent=4,
        sort_keys=True, separators=(",", ":")
    ))

def query_devices():
    pathElts = [
        "DatasetInfo",
        "Devices",
    ]
    # get serials if they are active
    return [create_query([(pathElts, [])], "analytics")]


def query_vlan_config(device_id):
    pathElts = [
        "Sysdb",
        "bridging",
        "config",
        "vlanConfig",
        Wildcard(),
    ]
    return [create_query([(pathElts, [])], device_id)]

def query_vlan_members(device_id,vlan_id):
    pathElts = [
        "Sysdb",
        "bridging",
        "config",
        "vlanConfig",
        {"value": vlan_id},
        "intf",
    ]
    return [create_query([(pathElts, [])], device_id)]

def query_ip_config(device_id,vlan_id):
    pathElts = [
        "Sysdb",
        "ip",
        "config",
        "ipIntfConfig",
        f"Vlan{vlan_id}",
    ]
    return [create_query([(pathElts, [])], device_id)]

def grpc_query(server,token,caCert,queries):
    with GRPCClient(server+':8443', token=token, key=None, ca=caCert, certs=None) as client:
        for query in queries:
            for batch in client.get(query):
                for notif in batch["notifications"]:
                    pretty_print(notif["updates"])
    return 0

def main():
    queries = []
    for server in cvp_servers:
        creds = login(server, cvp_user, cvp_pass)
        with open(tokenFile,"w") as f:
            f.write(creds[0])
            f.close()
        with open(certFile,"w") as f:
            f.write(creds[1])
            f.close()
        queries.append(query_devices())
        grpc_query(server,tokenFile,certFile,queries)
        #queries.append(query_vlan_config(dId))
        #queries.append(query_ip_config(dId))
        #queries.append(query_vlan_members(dId))


if __name__ == "__main__":
    main()
