# Policy
This is used to apply existing BIG-IP profiles and policy with Routes, Virtual Server and Transport server. The CRD resource defines the profile configuration for a virtual server in BIG-IP. 

  **Note**: VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource if the respective feature supported. Examples of features supported in all resource CRD (i.e. VirtualServer, TransportServer, and Policy) are waf and persistenceProfile.

## Components
### Policy Components

| Parameter    | Type   | Required | Default | Description                                                                                                                                                                           |
|--------------|--------|----------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| l7Policies   | Object | Optional | N/A     | BIG-IP l7Policies in Policy CR.                                                                                                                                                       |
| l3Policies   | Object | Optional | N/A     | BIG-IP l3Policies in Policy CR.                                                                                                                                                       |
| ltmPolicies  | Object | Optional | N/A     | BIG-IP LTM Policies in Policy CR.                                                                                                                                                     |
| iRules       | Object | Optional | N/A     | BIG-IP iRules in Policy CR.                                                                                                                                                           |
 | iRuleList    | List   | Optional | N/A     | List of BIGIP iRules to attach to virtuals via policy CR                                                                                                                              |
| profiles     | Object | Optional | N/A     | Various BIG-IP Profiles in Policy CR.                                                                                                                                                 |
| tcp          | Object | Optional | N/A     | BIG-IP TCP client and server profiles in Policy CR.                                                                                                                                   |
| snat         | String | Optional | auto    | Reference to SNAT pool on BIG-IP. The other allowed values are: `auto` (default) and `none`. VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource. |
| autoLastHop  | String | Optional | N/A     | Reference to Auto Last Hop on BIG-IP. Allowed values [default, auto, disable]                                                                                                         |
| poolSettings | Object | Optional | N/A     | Default pool settings to set on virtuals via  Policy CR                                                                                                                               |
| defaultPool  | Object | Optional | N/A     | Default pool to set on virtuals via Policy CR. VirtualServer CRD resource takes precedence over Policy CRD resource                                                                                                                                       |

### L7 Policy Components

| Parameter | Type   | Required | Default | Description                             |
| --------- | ------ | -------- | ------- | --------------------------------------- |
| waf       | String | Optional | N/A     | Pathname of existing BIG-IP WAF policy. |
| profileAdapt       | Object | Optional | N/A     | BIG-IP Adapt profile for Virtual Server. |

### L3 Policy Components

| Parameter            | Type          | Required | Default | Description                                                                                                                                                                                                    |
|----------------------|---------------|----------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| botDefense           | String        | Optional | N/A     | Pathname of the existing BIG-IP botDefense policy.                                                                                                                                                             |
| dos                  | String        | Optional | N/A     | Pathname of existing BIG-IP DOS policy.                                                                                                                                                                        |
| firewallPolicy       | String        | Optional | N/A     | Pathname of existing BIG-IP firewall(AFM) policy.                                                                                                                                                              |
| allowSourceRange     | String        | Optional | N/A     | Comma-separated list of CIDR addresses to allow inbound to services corresponding to VirtualServer CRD. Allowed values are comma-separated, CIDR formatted, IP addresses. For example: `1.2.3.4/32,2.2.2.0/24` |
| allowVlans           | List of Vlans | Optional | NA      | List of Vlan objects to allow traffic from towards virtual in BIGIP. Object configured in VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource.                             |
| ipIntelligencePolicy | String        | Optional | NA      | Pathname of existing BIG-IP ipIntelligence Policy.                                                                                                                                                             | 
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

**Note**:
* iRules is used to refrence a single iRule existing on BIGIP to attach it to http or https virtual server, whereas iRuleList can be used to refrence a list of iRules existing on BIGIP to attach them to http or https virtualservers through the policy CR.
* If both iRules and iRuleList are defined in the policy, iRuleList has higher precedence. 
* To disable default iRules created by CIS , configure "none" value on insecure or secure parameters through iRules or iRuleList spec to remove them from http or https virtualserver accordingly.
* In NextGen routes, iRuleList can be applied on either HTTP or HTTPS Virtual Server with the usage of httpServerPolicyCR in the route groups, whereas in all other cases it's applied to both HTTP and HTTPS VS(as of now).
* If only policyCR is used and httpServerPolicyCR is not used in a route group and iRuleList is specified in the policyCR, then it's applied to both HTTP and HTTPS virtual servers.
* If both policyCR and httpServerPolicyCR are used in a route group and iRuleList is specified only in the policyCR, then it's applied to only HTTPS virtual server.
* If both policyCR and httpServerPolicyCR are used in a route group and iRuleList is specified only in the httpServerPolicyCR, then it's applied to only HTTP virtual server.
* If both policyCR and httpServerPolicyCR are used in a route group and iRuleList is specified in policyCR and httpServerPolicyCR, then iRuleList specified in policyCR are applied to HTTPS VS and iRuleList specified in httpServerPolicyCR are applied to HTTP VS.
* We recommend using iRuleList over iRules as using iRuleList one can specify one or more iRules.
* We will be adding the support to specify httpServerPolicyCR in case of VS CRD as well to provide more control over which Virtual Server(HTTP/HTTPS) the policyCR is applied to.

### Profile Components

| Parameter              | Type           | Required | Default                                                           | Description                                                                                                                                                                                                                              |
|------------------------|----------------|----------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| tcp                    | Object         | Optional | N/A                                                               | TCP Client & Server Profiles                                                                                                                                                                                                             |
| udp                    | String         | Optional | N/A                                                               | Pathname of existing BIG-IP UDP profile.                                                                                                                                                                                                 |
| http                   | String         | Optional | N/A                                                               | Pathname of existing BIG-IP HTTP profile.                                                                                                                                                                                                |
| httpProfiles           | Object         | Optional | N/A                                                               | Pathname of existing BIG-IP HTTP profile for secured and unsecured virtual server.                                                                                                                                                       |
| https                  | String         | Optional | N/A                                                               | Pathname of existing BIG-IP SSL profile.                                                                                                                                                                                                 |
| http2                  | Object         | Optional | N/A                                                               | HTTP2 Client & Server Profiles                                                                                                                                                                                                           |
| logProfiles            | List of string | Optional | N/A                                                               | Pathname of existing BIG-IP log profile.                                                                                                                                                                                                 |
| requestLogProfile      | String         | Optional | N/A                                                               | Pathname of existing BIG-IP Request Log profile.                                                                                                                                                                                         |
| persistenceProfile     | String         | Optional | VirtualServer uses `cookie` TransportServer uses `source-address` | CIS uses the AS3 default persistence profile. VirtualServer or TransportServer CRD resource takes precedence over Policy CRD resource. Allowed values are existing BIG-IP Persistence profiles and custom Persistence profiles.          |
| profileMultiplex       | String         | Optional | N/A                                                               | CIS uses the AS3 default profileMultiplex profile. Allowed values are existing BIG-IP profileMultiplex profiles.                                                                                                                         |
| profileL4              | String         | Optional | basic                                                             | The default value is `basic` but it is not configurable if the profileL4 spec is not included in TS or Policy CR. Transport CRD resource takes precedence over Policy CRD resource. Allowed values are existing BIG-IP profileL4 profiles. |
| httpMrfRoutingEnabled  | Boolean        | Optional | N/A                                                               | Reference to Http mrf router on BIGIP.                                                                                                                                                                                                   |
| sslProfiles            | Object         | Optional | N/A                                                               | Reference to existing ssl profiles on BIGIP. Policy sslProfiles will have the highest precedence and will override route level profiles                                                                                                  |
| analyticsProfiles      | Object         | Optional | N/A                                                               | Configures different analytics profiles on BIGIP virtual server.                                                                                                                                                                         |
| profileWebSocket       | String         | Optional | N/A                                                               | Reference to existing BIG-IP websocket profile                                                                                                                                                                                           |
| htmlProfile            | String         | Optional | NA                                                                | Pathname of existing BIG-IP HTML profile. VirtualServer CRD resource takes precedence over Policy CRD. Allowed values are existing BIG-IP HTML profiles.                                                                                 |
| ftpProfile             | String         | Optional | N/A                                                               | Reference to existing BIG-IP FTP profile and is supported only for Transport Server                                                                                                                                                      |
| httpCompressionProfile | String         | Optional | N/A                                                               | Reference to existing BIG-IP HTTP Compression profile and is supported only for Virtual Server                                                                                                                                           |
| profileAnalyticsTcp | String         | Optional | N/A                                                               | Reference to existing BIG-IP TCP Analytics                                                                                                                                           |
| profileProtocolInspection | String      | Optional | N/A                                                               | Reference to existing BIG-IP Protocol Inspection profile. Supported for both Virtual Server and Transport Server                                                                                                                         |

**Note**:
* sslProfiles is only applicable to NextGen routes

### httpProfiles Components

| Parameter | Type   | Required | Default | Description                                   |
|-----------| ------ |----------|---------|-----------------------------------------------|
| insecure  | String | Optional | N/A     | Reference to existing HTTP profile on BIG-IP  |
| secure    | String | Optional | N/A     | Reference to existing HTTP profile on BIG-IP  |


### HTTP2 Profile Components

| Parameter | Type   | Required | Default | Description                                           |
| --------- | ------ | -------- |---------|-------------------------------------------------------|
| client    | String | Required | N/A     | Reference to existing ingress HTTP2 profile on BIG-IP |
| server    | String | Optional | N/A     | Reference to existing egress HTTP2 profile on BIG-IP  |

### TCP Profile Components

| Parameter | Type   | Required | Default         | Description                                                                                                                      |
| --------- | ------ | -------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| client    | String | Required | N/A Custom\_TCP | CIS uses the AS3 default TCP client profile. Allowed values are existing BIG-IP TCP Client profiles.                             |
| server    | String | Optional | N/A             | Allowed values are existing BIG-IP TCP Server profiles. **Note: Server TCP Profile can only be used along with Client profile.** |

### Analytics Profiles Components

| Parameter | Type   | Required | Default         | Description                                                                                                                      |
| --------- |--------| -------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| http    | String | Optional | N/A  | Reference to existing http analytics profile on BIGIP |

### SSL Profile Components

| Parameter      | Type  | Required | Default | Description                                                |
|----------------|-------|----------|---------|------------------------------------------------------------|
| clientProfiles | Array | Optional | N/A     | Reference to list of existing client SSL profiles on BIGIP |
| serverProfiles | Array | Optional | N/A     | Reference to list of existing server SSL profiles on BIGIP |

**Note**:
* SSL profile components are only applicable to NextGen routes

### poolSettings Components

| Parameter         | Type    | Required | Default | Description                                                                                         |
|-------------------|---------|----------|---------|-----------------------------------------------------------------------------------------------------|
| reselectTries     | Integer | Optional | 0       | reselectTries specifies the maximum number of attempts to find a responsive member for a connection |
| serviceDownAction | String  | Optional | None    | serviceDownAction specifies connection handling when member is non-responsive                       |
| slowRampTime      | Integer | Optional | 10      | BIG-IP AS3 sets the connection rate to a newly active member slowly during this interval (seconds)  |

### Default Pool Components

| PARAMETER           | TYPE              | REQUIRED | DEFAULT     | DESCRIPTION                                                                                                                             |
|---------------------|-------------------|----------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| service             | String            | Required | NA          | Service deployed in kubernetes cluster                                                                                                  |
| serviceNamespace    | String            | Optional | NA          | Namespace of service, define it if service is present in a namespace other than the one where Virtual Server Custom Resource is present |
| servicePort         | Integer or String | Required | NA          | Port to access Service.Could be service port, service port name or targetPort of the service                                            |                                                                                |
| loadBalancingMethod | String            | Optional | round-robin | Allowed values are existing BIG-IP Load Balancing methods for pools.                                                                    |
| nodeMemberLabel     | String            | Optional | NA          | List of Nodes to consider in NodePort Mode as BIG-IP pool members. This Option is only applicable for NodePort Mode                     |
| monitors            | monitor           | Optional | NA          | Specifies multiple monitors for VS Pool                                                                                                 |
| serviceDownAction   | String            | Optional | none        | Specifies connection handling when member is non-responsive                                                                             |
| reselectTries       | Integer           | Optional | 0           | Maximum number of attempts to find a responsive member for a connection                                                                 |
| reference           | String            | Required | NA          | Allowed values are **bigip** or **service**                                                                                             |
| name                | String            | Optional | NA          | pool name or reference to the pool name existing on bigip                                                                               |
| staticPoolMembers   | Object            | Optional | NA          | List of static pool member objects specifying fixed IP addresses and ports for default pool                                             |

### Static Pool Member Object Components

| PARAMETER   | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                      |
|-------------|---------|----------|---------|--------------------------------------------------|
| address     | String  | Required | NA      | IP address of the pool member                    |
| port        | Integer | Required | NA      | Port number for the pool member                  |

**Adapt Profile Components**
| PARAMETER        | TYPE    | REQUIRED | DEFAULT | DESCRIPTION                                                                                   |
|------------------|---------|----------|---------|-----------------------------------------------------------------------------------------------|
| request             | String  | Optional | NA      | Reference to existing request adapt profile on BIG-IP.                                  |
| response           | String  | Optional | NA      | Reference to existing response adapt profile on BIG-IP.                            |

**Note**
  * profileAdapt in Virtual Server CR takes precedence over profileAdapt in Policy CR.