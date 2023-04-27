# Policy
Policy is used to apply existing BIG-IP profiles and policy with Routes, Virtual Server and Transport server. The Policy CRD resource defines the profile configuration for a virtual server in BIG-IP. 

  **Note**: VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource if the respective feature supported. Examples of features supported in all resource CRD (i.e. VirtualServer, TransportServer, and Policy) are waf and persistenceProfile.

## Components
### Policy Components

| Parameter   | Type   | Required | Default | Description                                                                                                                                                                           |
|-------------| ------ | -------- |---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| l7Policies  | Object | Optional | N/A     | BIG-IP l7Policies in Policy CR.                                                                                                                                                       |
| l3Policies  | Object | Optional | N/A     | BIG-IP l3Policies in Policy CR.                                                                                                                                                       |
| ltmPolicies | Object | Optional | N/A     | BIG-IP LTM Policies in Policy CR.                                                                                                                                                     |
| iRules      | Object | Optional | N/A     | BIG-IP iRules in Policy CR.                                                                                                                                                           |
 | iRuleList  |  Object | Optional | N/A    | List of BIGIP iRules to attach to virtuals via policy CR                                                                                                                              |
| profiles    | Object | Optional | N/A     | Various BIG-IP Profiles in Policy CR.                                                                                                                                                 
| analyticsProfiles    | Object | Optional | N/A     | Configures different analytics profiles on BIGIP virtual server.                                                                                                                      |
| tcp         | Object | Optional | N/A     | BIG-IP TCP client and server profiles in Policy CR.                                                                                                                                   |
| snat        | String | Optional | auto    | Reference to SNAT pool on BIG-IP. The other allowed values are: `auto` (default) and `none`. VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource. |
| autoLastHop    | String | Optional | N/A     | Reference to Auto Last Hop on BIG-IP. Allowed values [default, auto, disable]                                                                                                         |

### L7 Policy Components

| Parameter | Type   | Required | Default | Description                             |
| --------- | ------ | -------- | ------- | --------------------------------------- |
| waf       | String | Optional | N/A     | Pathname of existing BIG-IP WAF policy. |

### L3 Policy Components

| Parameter        | Type   | Required | Default | Description                                                                                                                                                                                                    |
| ---------------- | ------ | -------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| botDefense       | String | Optional | N/A     | Pathname of the existing BIG-IP botDefense policy.                                                                                                                                                             |
| dos              | String | Optional | N/A     | Pathname of existing BIG-IP DOS policy.                                                                                                                                                                        |
| firewallPolicy   | String | Optional | N/A     | Pathname of existing BIG-IP firewall(AFM) policy.                                                                                                                                                              |
| allowSourceRange | String | Optional | N/A     | Comma-separated list of CIDR addresses to allow inbound to services corresponding to VirtualServer CRD. Allowed values are comma-separated, CIDR formatted, IP addresses. For example: `1.2.3.4/32,2.2.2.0/24` |
| allowVlans       | List of Vlans | Optional | NA | List of Vlan objects to allow traffic from towards virtual in BIGIP. Object configured in VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource.|
| ipIntelligencePolicy       | String | Optional | NA | Pathname of existing BIG-IP ipIntelligence Policy.                                                                                                                                                                        | 
### LTM Policy Components

| Parameter | Type   | Required | Default | Description                                                         |
| --------- | ------ | -------- | ------- | ------------------------------------------------------------------- |
| insecure  | String | Optional | N/A     |                                                                     |
| secure    | String | Optional | N/A     |                                                                     |
| priority  | String | Optional | N/A     | Defines the level of priority. Allowed values are `low` and `high`. |

### iRules Components

| Parameter | Type   | Required | Default | Description                                                     |
| --------- | ------ | -------- | ------- |-----------------------------------------------------------------|
| insecure  | String | Optional | N/A     | Pathname of existing BIG-IP iRule.                              |
| secure    | String | Optional | N/A     | Pathname of existing BIG-IP iRule.                              |
| priority  | String | Optional | N/A     | Defines the level of priority. Allowed values are `low` and `high`. |

### iRuleList Components

| Parameter | Type  | Required | Default | Description                                                          |
| --------- |-------| -------- | ------- | -------------------------------------------------------------------      |
| insecure  | Array | Optional | N/A     | List of existing BIG-IP iRules to attach to insecure virtual on BIGIP |                                  
| secure    | Array | Optional | N/A     | List of existing BIG-IP iRules to attach to secure virtual on BIGIP |                                 
| priority  | Array | Optional | N/A     | Defines the level of priority. Allowed values are `low` and `high`. |

**Note**:
* iRules is used to refrence a single iRule existing on BIGIP to attach it to http or https virtual server, whereas iRuleList can be used to refrence a list of iRules existing on BIGIP to attach them to http or https virtualservers through the policy CR.
* If both iRules and iRuleList are defined in the policy, iRuleList has higher precedence. 
* To disable default iRules created by CIS , configure "none" value on insecure or secure parameters through iRules or iRuleList spec to remove them from http or https virtualserver accordingly.

### Profile Components

| Parameter             | Type           | Required | Default                                                           | Description                                                                                                                                                                                                                                |
|-----------------------| -------------- | -------- | ----------------------------------------------------------------- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| udp                   | String         | Optional | N/A                                                               | Pathname of existing BIG-IP UDP profile.                                                                                                                                                                                                   |
| http                  | Object         | Optional | N/A                                                               | Pathname of existing BIG-IP HTTP profile.                                                                                                                                                                                                  |
| https                 | String         | Optional | N/A                                                               | Pathname of existing BIG-IP SSL profile.                                                                                                                                                                                                   |
| http2                 | Object         | Optional | N/A                                                               | Pathname of existing BIG-IP HTTP2 profile.                                                                                                                                                                                                 |
| logProfiles           | List of string | Optional | N/A                                                               | Pathname of existing BIG-IP log profile.                                                                                                                                                                                                   |
| persistenceProfile    | String         | Optional | VirtualServer uses `cookie` TransportServer uses `source-address` | CIS uses the AS3 default persistence profile. VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource. Allowed values are existing BIG-IP Persistence profiles and custom Persistence profiles.            |
| profileMultiplex      | String         | Optional | N/A                                                               | CIS uses the AS3 default profileMultiplex profile. Allowed values are existing BIG-IP profileMultiplex profiles.                                                                                                                           |
| profileL4             | String         | Optional | basic                                                             | The default value is `basic` but it is not configurable if the profileL4 spec is not included in TS or Policy CR. Transport CRD resource takes precedence over Policy CRD resource. Allowed values are existing BIG-IP profileL4 profiles. |
| httpMrfRoutingEnabled | Boolean | Optional | N/A     | Reference to Http mrf router on BIGIP. |

### TCP Profile Components

| Parameter | Type   | Required | Default         | Description                                                                                                                      |
| --------- | ------ | -------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| client    | String | Required | N/A Custom\_TCP | CIS uses the AS3 default TCP client profile. Allowed values are existing BIG-IP TCP Client profiles.                             |
| server    | String | Optional | N/A             | Allowed values are existing BIG-IP TCP Server profiles. **Note: Server TCP Profile can only be used along with Client profile.** |

### Analytics Profiles Components

| Parameter | Type   | Required | Default         | Description                                                                                                                      |
| --------- | ------ | -------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| http    | Object | Optional | N/A  | CIS will configure http analytics profile on virtual server.

### HTTP Analytics Profile Components

| Parameter | Type   | Required | Default         | Description                                                                                                                      |
| --------- | ------ | -------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| bigip    | String | Optional | N/A  | Reference to existing http analytics profile on BIGIP
| apply    | String | Optional | N/A  | allowed values are [http, https , both] 

### HTTP Profile Components

| Parameter | Type   | Required | Default         | Description                                                                                                                      |
| --------- | ------ | -------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| bigip    | String | Optional | N/A  | Reference to existing http profile on BIGIP
| apply    | String | Optional | N/A  | allowed values are [http, https , both] 

### HTTP2 Profile Components

| Parameter | Type   | Required | Default | Description                                           |
| --------- | ------ | -------- |---------|-------------------------------------------------------|
| client    | String | Required | N/A     | Reference to existing ingress HTTP2 profile on BIG-IP |
| server    | String | Optional | N/A     | Reference to existing egress HTTP2 profile on BIG-IP  |
