# DefaultRouteDomain Support

This section demonstrates the option to configure default-route-domain in CIS deployment.
Default Route Domain is supported for CRD resources and hence this feature is supported even for multipartition feature.
* Option which can be used to configure default-route-domain:

```
--default-route-domain=5
```
* By default `default-route-domain` is 0

```Note: Validated CRD resources with the below BIGIP RouteDomain configuration ```

##Route Domain Configuration on BIGIP:
```
Steps followed to configure BIGIP RouteDomain:
1. Remove the Routes, selfIP,VLAN and Tunnel objects participating in CIS to discover end-apps(Pool Members).
    Routes(Recommended for OVN-iCNI):
      tmsh -q -c 'cd /Common; delete net route all'
      tmsh -q -c 'cd /test; delete net route all'
      *Note: Remove in CIS-managed partition if exists
    SELFIPs:
      tmsh -q -c 'cd /Common; delete net self selfip.external'
      tmsh -q -c 'cd /Common; delete net self selfip.internal'
      tmsh -q -c 'cd /test; delete net self openshift-selfip'
    VLANs:
      tmsh -q -c 'cd /Common; delete net vlan external'
      tmsh -q -c 'cd /Common; delete net vlan internal'
    Tunnel:
      tmsh -q -c 'cd /test; delete net tunnels tunnel vxlan-tunnel-mp'        
    *Note: where "test" is CIS-managed Partition defined in CIS deployment spec with --bigip-partition configuration parameter
    
2. Create RouteDomain with the desired number in the CIS managed Partition
    tmsh -q -c 'cd /Common; create net route-domain rd-5 id 5'
    
3. Ensure the above Route domain is configured as default route domain for CIS managed partition
    tmsh -q -c 'cd /Common; modify auth partition test default-route-domain 5'
      
4. Add the Step 1 VLAN, SELFIP, Tunnel and Routes objects in the CIS managed Partition. 
    VLANs:
      tmsh -q -c 'cd /test; create net vlan internal interfaces add { 1.1 }'
      tmsh -q -c 'cd /test; create net vlan external interfaces add { 1.2 }'
    SELFIPs:
      tmsh -q -c 'cd /test; create net self selfip.internal address 10.4.1.111/14 allow-service all vlan internal'
      tmsh -q -c 'cd /test; create net self selfip.external address 10.8.3.11/14 allow-service all vlan external'
    Tunnel:  
      tmsh -q -c 'cd /test; create net tunnels tunnel vxlan-tunnel-mp profile vxlan-multipoint local-address 10.4.1.111 remote-address any'
    Tunnel SELFIP:
      tmsh -q -c 'cd /test; create net self openshift-selfip address 10.131.255.1/14 vlan vxlan-tunnel-mp'  
    Default Routes: (Recommended for OVN-iCNI)
      tmsh -q -c 'cd /test; create net route 10.128.0.0/23 gw 10.4.1.115'
      tmsh -q -c 'cd /test; create net route 10.129.0.0/23 gw 10.4.1.116'
      tmsh -q -c 'cd /test; create net route 10.130.0.0/23 gw 10.4.1.117'
      where 10.4.1.x are the cluster node IPs and 10.xxx.0.0/23 are the POD networks assigned to the respective cluster Node (acting as gw)
          
5. Start CIS
```

#### Note: CIS creates new bigip-partitions based on the 'partition' spec parameter in VS/TS CRD and inherits the CIS-managed-Partition Route domain to the new partitions.

