# Policy
Policy is used to apply existing BIG-IP profiles and policy with Routes, Virtual Server and Transport server. The Policy CRD resource defines the profile configuration for a virtual server in BIG-IP. 

  **Note**: VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource if the respective feature supported. Examples of features supported in all resource CRD (i.e. VirtualServer, TransportServer, and Policy) are waf and persistenceProfile.

## Components
### Policy Components

| Parameter   | Type   | Required | Default | Description                                                                                                                                                                           |
| ----------- | ------ | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| l7Policies  | Object | Optional | N/A     | BIG-IP l7Policies in Policy CR.                                                                                                                                                       |
| l3Policies  | Object | Optional | N/A     | BIG-IP l3Policies in Policy CR.                                                                                                                                                       |
| ltmPolicies | Object | Optional | N/A     | BIG-IP LTM Policies in Policy CR.                                                                                                                                                     |
| iRules      | Object | Optional | N/A     | BIG-IP iRules in Policy CR.                                                                                                                                                           |
| profiles    | Object | Optional | N/A     | Various BIG-IP Profiles in Policy CR.                                                                                                                                                 |
| tcp         | Object | Optional | N/A     | BIG-IP TCP client and server profiles in Policy CR.                                                                                                                                   |
| snat        | String | Optional | auto    | Reference to SNAT pool on BIG-IP. The other allowed values are: `auto` (default) and `none`. VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource. |

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
| allowSourceRange | String | Optional | N/A     | Comma-separated list of CIDR addresses to allow inbound to services corresponding to VirtualServer CRD. Allowed values are comma-separated, CIDR formatted, IP addresses. For example: `1.2.3.4/32,2.2.2.0/24` 
| allowVlans       | List of Vlans | Optional | NA | List of Vlan objects to allow traffic from towards virtual in BIGIP. Object configured in VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource.|
| ipIntelligencePolicy       | String | Optional | NA | Pathname of existing BIG-IP ipIntelligence Policy.                                                                                                                                                                        | 
### LTM Policy Components

| Parameter | Type   | Required | Default | Description                                                         |
| --------- | ------ | -------- | ------- | ------------------------------------------------------------------- |
| insecure  | String | Optional | N/A     |                                                                     |
| secure    | String | Optional | N/A     |                                                                     |
| priority  | String | Optional | N/A     | Defines the level of priority. Allowed values are `low` and `high`. |

### iRules Components

| Parameter | Type   | Required | Default | Description                                                         |
| --------- | ------ | -------- | ------- | ------------------------------------------------------------------- |
| insecure  | String | Optional | N/A     | Pathname of existing BIG-IP iRule.                                  |
| secure    | String | Optional | N/A     | Pathname of existing BIG-IP iRule.                                  |
| priority  | String | Optional | N/A     | Defines the level of priority. Allowed values are `low` and `high`. |

### Profile Components

| Parameter          | Type           | Required | Default                                                           | Description                                                                                                                                                                                                                                |
| ------------------ | -------------- | -------- | ----------------------------------------------------------------- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| udp                | String         | Optional | N/A                                                               | Pathname of existing BIG-IP UDP profile.                                                                                                                                                                                                   |
| http               | String         | Optional | N/A                                                               | Pathname of existing BIG-IP HTTP profile.                                                                                                                                                                                                  |
| https              | String         | Optional | N/A                                                               | Pathname of existing BIG-IP SSL profile.                                                                                                                                                                                                   |
| http2              | String         | Optional | N/A                                                               | Pathname of existing BIG-IP HTTP2 profile.                                                                                                                                                                                                 |
| logProfiles        | List of string | Optional | N/A                                                               | Pathname of existing BIG-IP log profile.                                                                                                                                                                                                   |
| persistenceProfile | String         | Optional | VirtualServer uses `cookie` TransportServer uses `source-address` | CIS uses the AS3 default persistence profile. VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource. Allowed values are existing BIG-IP Persistence profiles and custom Persistence profiles.            |
| profileMultiplex   | String         | Optional | N/A                                                               | CIS uses the AS3 default profileMultiplex profile. Allowed values are existing BIG-IP profileMultiplex profiles.                                                                                                                           |
| profileL4          | String         | Optional | basic                                                             | The default value is `basic` but it is not configurable if the profileL4 spec is not included in TS or Policy CR. Transport CRD resource takes precedence over Policy CRD resource. Allowed values are existing BIG-IP profileL4 profiles. |

### TCP Profile Components

| Parameter | Type   | Required | Default         | Description                                                                                                                      |
| --------- | ------ | -------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| client    | String | Required | N/A Custom\_TCP | CIS uses the AS3 default TCP client profile. Allowed values are existing BIG-IP TCP Client profiles.                             |
| server    | String | Optional | N/A             | Allowed values are existing BIG-IP TCP Server profiles. **Note: Server TCP Profile can only be used along with Client profile.** |
