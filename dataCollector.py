#!/usr/bin/env python3
import ipaddress
import json
import requests
import ssl
from cloudvision.Connector.codec import Wildcard
from cloudvision.Connector.grpc_client import GRPCClient, create_query

### CVP Data collection script. Grabs active devices, and then identifies SVIs, and interfaces that are in use for them.

def login(url_prefix, username, password):
    connect_timeout = 10
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    session = requests.Session()
    authdata = {"userId": username, "password": password}
    response = session.post(
        "https://" + url_prefix + "/web/login/authenticate.do",
        data=json.dumps(authdata),
        headers=headers,
        timeout=connect_timeout,
        verify=False,
    )
    if response.json()["sessionId"]:
        token = response.json()["sessionId"]
        sslcert = ssl.get_server_certificate((url_prefix, 8443))
        return [token, sslcert]


def query_devices(client):
    pathElts = [
        "DatasetInfo",
        "Devices",
    ]
    query = [create_query([(pathElts, [])], "analytics")]

    # yield device serials (device_id) if they are active
    for devices in grpc_query(client, query):
        for device, data in devices.items():
            if data["status"] == "active":
                yield {
                    "hostname": data["hostname"],
                    "serial": device,
                }


def query_vlan_config(client, device_id):
    pathElts = [
        "Sysdb",
        "bridging",
        "config",
        "vlanConfig",
        Wildcard(),
    ]
    query = [create_query([(pathElts, [])], device_id)]

    # yield dictionaries containing vlan ID and name
    for vlan in grpc_query(client, query):
        if vlan["internal"]:  # ignore internal vlans
            continue
        yield {
            "id": vlan["vlanId"]["value"],
            "name": vlan["configuredName"],
        }


def query_vlan_members(client: GRPCClient, device_id, vlan_id):
    pathElts = [
        "Sysdb",
        "bridging",
        "config",
        "vlanConfig",
        {"value": vlan_id},
        "intf",
    ]
    query = [create_query([(pathElts, [])], device_id)]

    for intfs in grpc_query(client, query):
        yield from intfs.keys()


def query_ip_config(client, device_id, vlan_id):
    pathElts = [
        "Sysdb",
        "ip",
        "config",
        "ipIntfConfig",
        f"Vlan{vlan_id}",
    ]
    query = [create_query([(pathElts, [])], device_id)]

    for svi in grpc_query(client, query):
        ip_addr = svi["addrWithMask"]
        ip_virtual_addr = svi["virtualAddrWithMask"]
        for addr in ip_addr, ip_virtual_addr:
            if addr == "0.0.0.0/0":
                yield None
            else:
                yield addr


def main(token=None, certs=None, ca=None, key=None):
    ### Modify these lines ###
    cvp_servers = ["192.168.255.50"]
    cvp_user = "admin"
    cvp_pass = "Arista123"
    ### Do not modify below this line ###
    token = "token.txt"
    ca = "cert.crt"
    for server in cvp_servers:
        creds = login(server, cvp_user, cvp_pass)
        with open(token, "w") as f:
            f.write(creds[0])
            f.close()
        with open(ca, "w") as f:
            f.write(creds[1])
            f.close()
        data = []
        with GRPCClient(
            f"{server}:8443", token=token, key=key, ca=ca, certs=certs
        ) as client:
            for device in query_devices(client):
                for vlan in query_vlan_config(client, device["serial"]):
                    intfs = query_vlan_members(client, device["serial"], vlan["id"])
                    if "Cpu" not in intfs:  # i.e., vlan does not have an SVI
                        continue
                    addrs = query_ip_config(client, device["serial"], vlan["id"])
                    for addr in addrs:
                        if addr:
                            break
                    network = ipaddress.ip_network(addr, strict=False)
                    data.append(
                        {   
                            "server": server,
                            "device": {
                                "hostname": device["hostname"],
                                "serial": device["serial"],
                            },
                            "vlan": {
                                "id": vlan["id"],
                                "name": vlan["name"],
                                "network": str(network),
                            },
                            "intfs": [intf for intf in intfs],
                        }
                    )
        print(json.dumps(data, indent=4))

def grpc_query(client, query):
    for batch in client.get(query):
        update = {}
        for notif in batch["notifications"]:
            update.update(notif["updates"])
        yield update


if __name__ == "__main__":
    main()
