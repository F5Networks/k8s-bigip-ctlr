# Kubernetes User Guide with BIG-IP High Availability (HA) Configuration

This page is created to document K8S 1.20 with integration of CIS and BIGIP in a HA cluster 

# Note

Environment parameters

* K8S 1.20 - one master and two worker nodes
* CIS 2.4.0
* AS3: 3.26
* BIG-IP 15.1

# Kubernetes 1.20 Install

K8S is installed on RHEL 7.5 on ESXi

* ks8-1-20-master  
* ks8-1-20-node1
* ks8-1-20-node2

## Prerequisite

**Note** This solution works but you cannot have ANY floating IP addresses

**About configuring VXLAN tunnels on high availability BIG-IP device pairs**

By default, the BIG-IP® system synchronizes all existing tunnel objects in its config sync operation. This operation requires that the local IP address of a tunnel be set to a floating self IP address. In a high availability (HA) configuration, any tunnel with a floating local IP address would be available only on the active device, which would prevent some features, such as health monitors, from using the tunnel on the standby device. To make a tunnel available on both the active and standby devices, you need to set the local IP address to a non-floating self IP address, which then requires that you exclude tunnels from the config sync operation. To disable the synchronization of tunnel objects, you can set a bigdb variable on both devices.

### Disabling config sync for tunnels
In a OVN Kubernetes environment, you might want to disable config sync behavior for tunnels, such as when you need to make VXLAN tunnels functional on all devices in a BIG-IP® device group configured for high availability. The tunnel config sync setting applies to all tunnels created on the BIG-IP device. Important: Disable config sync on both the active and standby devices before you create any tunnels.

Log in to the tmsh command-line utility for the BIG-IP system. Determine whether the variable is already disabled, by typing this command.

    tmsh list sys db iptunnel.configsync value

Disable the variable.

    tmsh modify sys db iptunnel.configsync value disable

Save the configuration.

    tmsh save sys config

Validate the db value

```
tmsh list sys db iptunnel.configsync value
sys db iptunnel.configsync {
    value "disable"
```

**Now you can create tunnels with non-floating local IP addresses on both the active and standby devices** More information on Configuring Network Virtualization Tunnels [techdocs](https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-tmos-tunnels-ipsec-12-1-0/2.html)

## Create BIG-IP Nodes (vxlan)

Find the VTEP MAC address

```
(tmos)# show net tunnels tunnel fl-vxlan all-properties

-------------------------------------------------
Net::Tunnel: fl-vxlan
-------------------------------------------------
MAC Address                     00:50:56:bb:70:8b
Interface Name                           fl-vxlan

Incoming Discard Packets                        0
Incoming Error Packets                          0
Incoming Unknown Proto Packets                  0
Outgoing Discard Packets                        0
Outgoing Error Packets                         95
HC Incoming Octets                         109.9K
HC Incoming Unicast Packets                  1.0K
HC Incoming Multicast Packets                   0
HC Incoming Broadcast Packets                   0
HC Outgoing Octets                          97.9K
HC Outgoing Unicast Packets                  1.0K
HC Outgoing Multicast Packets                   0
HC Outgoing Broadcast Packets                   0
```

## Create two “dummy” Kubernetes Node for each BIGIP device

Include all of the flannel Annotations. Define the backend-data and public-ip Annotations with data from the BIG-IP VXLAN:

```
apiVersion: v1
kind: Node
metadata:
  name: bigip1
  annotations:
    #Replace MAC with your BIGIP Flannel VXLAN Tunnel MAC
    flannel.alpha.coreos.com/backend-data: '{"VtepMAC":"00:50:56:bb:70:8b"}'
    flannel.alpha.coreos.com/backend-type: "vxlan"
    flannel.alpha.coreos.com/kube-subnet-manager: "true"
    #Replace IP with Self-IP for your deployment
    flannel.alpha.coreos.com/public-ip: "192.168.200.91"
spec:
  #Replace Subnet with your BIGIP Flannel Subnet
  podCIDR: "10.244.20.0/24
```

**Note: Second node create a unique podCIDR**

* f5-bigip-node-91.yaml [repo](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/k8s-ha/big-ip-91/f5-bigip-node-91.yaml)
* f5-bigip-node-92.yaml [repo](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/k8s-ha/big-ip-91/f5-bigip-node-92.yaml)

## Create self-ip

bigip1

* tmsh create net tunnels vxlan fl-vxlan port 8472 flooding-type none
* tmsh create net tunnels tunnel fl-vxlan key 1 profile fl-vxlan local-address 192.168.200.91
* tmsh create net self **10.244.20.91** address **10.244.20.91/255.255.0.0** allow-service none vlan fl-vxlan

bigip2

* tmsh create net tunnels vxlan fl-vxlan port 8472 flooding-type none
* tmsh create net tunnels tunnel fl-vxlan key 1 profile fl-vxlan local-address 192.168.200.92
* tmsh create net self **10.244.21.92** address **10.244.21.92/255.255.0.0** allow-service none vlan fl-vxlan

## Example self-ip configuration

bigip1

![bigip1](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/k8s-ha/diagrams/2021-04-13_10-08-15.png)

bigip2

![bigip2](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/k8s-ha/diagrams/2021-04-13_10-10-04.png)

## Deploy CIS for each BIG-IP

Configuration options available in the CIS controller
```
    spec: 
      containers: 
        - 
          args: 
            - "--bigip-username=$(BIGIP_USERNAME)"
            - "--bigip-password=$(BIGIP_PASSWORD)"
            - "--bigip-url=192.168.200.91"
            - "--bigip-partition=k8s"
            - "--namespace=default"
            - "--pool-member-type=cluster"
            - "--flannel-name=fl-vxlan"
            - "--log-level=DEBUG"
            - "--insecure=true"
            - "--log-as3-response=true"
            - "--custom-resource-mode=true"
          command: 
```

bigip1
* f5-bigip-ctlr-deployment-91.yaml [repo](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/k8s-ha/big-ip-91/f5-bigip-ctlr-deployment-91.yaml)

bigip2
* f5-bigip-ctlr-deployment-92.yaml [repo](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/k8s-ha/big-ip-92/f5-bigip-ctlr-deployment-92.yaml)

## Disclosures

This solution works but you cannot have ANY floating IP addresses. If the K8S nodes are pointing to the BIG-IP internal floating self-ip you would need to remove the self-ip and configure a default gateway forwarding VIP as shown in the diagram below. This is created in Common
 
 ![defaultgatewa](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/_static/user_guides/k8s-ha/diagrams/2021-04-13_13-17-33.png)