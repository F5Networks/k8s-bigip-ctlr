F5 BIG-IP Controller for Kubernetes
===================================

|Slack|

.. toctree::
    :hidden:
    :maxdepth: 2

    RELEASE-NOTES
    /_static/ATTRIBUTIONS

The |kctlr-long| lets you manage your F5 BIG-IP device from `Kubernetes`_ or `OpenShift`_ using either environment's native CLI/API.

|release-notes|

|attributions|

:fonticon:`fa fa-download` :download:`Attributions.md </_static/ATTRIBUTIONS.md>`

Features
--------
- Dynamically creates, manages, and destroys BIG-IP objects.
- Forwards traffic from the BIG-IP device to `Kubernetes clusters`_ via `NodePort`_ or `ClusterIP`_.
- Support for F5 `iApps`_.
- Handles F5-specific VirtualServer objects created in Kubernetes.
- Handles standard `Kubernetes Ingress`_ objects using F5-specific extensions.
- Handles route configuration on the BIG-IP system (**OpenShift only**).

Guides
------
See the |kctlr-long| `user documentation`_.

Overview
--------
The |kctlr-long| is a Docker container that runs in a `Kubernetes`_ Pod.
It uses `F5 Resource`_ s to determine:

- what objects to configure on your BIG-IP system, and
- to which `Kubernetes Service`_ those objects belong.

The |kctlr| watches the Kubernetes API for the creation, modification, or deletion of Kubernetes objects.
For some Kubernetes objects, the Controller responds by creating, modifying, or deleting objects in the BIG-IP system.
The |kctlr| handles the following Kubernetes objects:

- :ref:`F5 Resource ConfigMap <f5 resource configmap properties>` -- creates Service-specific frontend virtual servers and/or pools on the BIG-IP system.
- `Kubernetes Ingress`_  -- creates a single front-end virtual server on the BIG-IP system that uses L7 policies to route to individual Services.
- `OpenShift Route`_ -- enables route-handling (specific to OpenShift).

One Controller can handle a mix of these objects simultaneously. See below for specifics regarding the handling of these objects.

For example, when run in `NodePort mode`_, the |kctlr| does the following:

#. Discovers a new F5 ``virtualServer`` resource.
#. Creates a new virtual server object in the specified partition on the BIG-IP system. [#objectpartition]_
#. Creates a pool member on the virtual server for each node in the cluster. [#nodeportmode]_
#. Monitors F5 resources, and linked Kubernetes resources, for changes.
#. Reconfigures the BIG-IP system when it discovers changes.

The BIG-IP system handles traffic for the Service at the specified virtual address and load balances to all nodes in the cluster.
Within the cluster, the allocated NodePort load balances traffic to all pods.

.. danger::
 
   The |kctlr| monitors the BIG-IP partition it manages for configuration changes. If it discovers changes, the Controller reapplies its own configuration to the BIG-IP system.
   
   F5 does not recommend making configuration changes to objects in any partition managed by the |kctlr| via any other means (for example, the configuration utility, TMOS, or by syncing configuration with another device or service group). Doing so may result in disruption of service or unexpected behavior.

.. _configuration parameters:

Controller Configuration Parameters
-----------------------------------
All configuration parameters below are global to the |kctlr|.

General
```````

+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| Parameter             | Type    | Required | Default           | Description                             | Allowed Values |
+=======================+=========+==========+===================+=========================================+================+
| log-level             | string  | Optional | INFO              | Log level                               | INFO,          |
|                       |         |          |                   |                                         | DEBUG,         |
|                       |         |          |                   |                                         | CRITICAL,      |
|                       |         |          |                   |                                         | WARNING,       |
|                       |         |          |                   |                                         | ERROR          |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| node-poll-interval    | integer | Optional | 30                | In seconds, interval at which           |                |
|                       |         |          |                   | to poll the cluster for its             |                |
|                       |         |          |                   | node members.                           |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| python-basedir        | string  | Optional | /app/python       | Path to python utilities                |                |
|                       |         |          |                   | directory                               |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| verify-interval       | integer | Optional | 30                | In seconds, interval at which           |                |
|                       |         |          |                   | to verify the BIG-IP                    |                |
|                       |         |          |                   | configuration.                          |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+

BIG-IP system
`````````````

+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| Parameter             | Type    | Required | Default           | Description                             | Allowed Values |
+=======================+=========+==========+===================+=========================================+================+
| bigip-partition       | string  | Required | n/a               | The BIG-IP partition in which           |                |
|                       |         |          |                   | to configure objects.                   |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| bigip-password        | string  | Required | n/a               | BIG-IP iControl REST password           |                |
|                       |         |          |                   | [#secrets]_                             |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| bigip-url             | string  | Required | n/a               | BIG-IP admin IP address                 |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| bigip-username        | string  | Required | n/a               | BIG-IP iControl REST username           |                |
|                       |         |          |                   | [#username]_                            |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+

Kubernetes
``````````

+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| Parameter             | Type    | Required | Default           | Description                             | Allowed Values |
+=======================+=========+==========+===================+=========================================+================+
| default-ingress-ip    | string  | Optional | n/a               | The controller configures a virtual     |                |
|                       |         |          |                   | server at this IP address for all       |                |
|                       |         |          |                   | Ingresses with the annotation:          |                |
|                       |         |          |                   | ``virtual-server.f5.com/ip:             |                |
|                       |         |          |                   | 'controller-default'``                  |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| kubeconfig            | string  | Optional | ./config          | Path to the *kubeconfig* file           |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| namespace             | string  | Optional | All               | Kubernetes namespace(s) to watch        |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | - may be a comma-separated list         |                |
|                       |         |          |                   | - watches all namespaces by default     |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| namespace-label       | string  | Optional | n/a               | Tells the ``k8s-bigip-ctlr`` to watch   |                |
|                       |         |          |                   | any namespace with this label           |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| node-label-selector   | string  | Optional | n/a               | Tells the ``k8s-bigip-ctlr`` to watch   |                |
|                       |         |          |                   | only nodes with this label              |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| pool-member-type      | string  | Optional | nodeport          | The type of BIG-IP pool members you want| cluster,       |
|                       |         |          |                   | to create. [#username]_                 | nodeport       |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | Use ``cluster`` to create pool members  |                |
|                       |         |          |                   | for each of the endpoints for the       |                |
|                       |         |          |                   | Service (the pod's InternalIP)          |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | Use ``nodeport`` to create pool members |                |
|                       |         |          |                   | for each schedulable node using the     |                |
|                       |         |          |                   | Service's NodePort.                     |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| resolve-ingress-names | string  | Optional | n/a               | Tells the controller to resolve the     |                |
|                       |         |          |                   | first Host in an Ingress resource to an |                |
|                       |         |          |                   | IP address. This IP address will be     |                |
|                       |         |          |                   | used as the virtual server address for  |                |
|                       |         |          |                   | the Ingress resource.                   |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | A value of "LOOKUP" will use local DNS  |                |
|                       |         |          |                   | to resolve the Host. Any other value    |                |
|                       |         |          |                   | is a custom DNS server and the          |                |
|                       |         |          |                   | controller sends resolution queries     |                |
|                       |         |          |                   | through that server instead.            |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | Specifying the flag with no argument    |                |
|                       |         |          |                   | will default to LOOKUP.                 |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| running-in-cluster    | boolean | Optional | true              | Indicates whether or not a              | true, false    |
|                       |         |          |                   | kubernetes cluster started              |                |
|                       |         |          |                   | ``k8s-bigip-ctlr``                      |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| use-node-internal     | boolean | Optional | true              | filter Kubernetes InternalIP            | true, false    |
|                       |         |          |                   | addresses for pool members              |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| use-secrets           | boolean | Optional | true              | Tells the controller whether or not     | true, false    |
|                       |         |          |                   | to load SSL profiles from Kubernetes    |                |
|                       |         |          |                   | Secrets for Ingresses and ConfigMaps.   |                |
|                       |         |          |                   | If false, the controller will only use  |                |
|                       |         |          |                   | profiles from the BIG-IP system.        |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+

.. note::

  Use the ``node-label-selector`` parameter if you only want the controller to manage specific nodes from the cluster.
  For example, the BIG-IP device may not be able to reach certain nodes, or the BIG-IP device already manages certain
  nodes. Therefore, the controller should only watch the nodes that match the environmental constraints (by using a label).

VXLAN
`````````````

+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| Parameter             | Type    | Required | Default           | Description                             | Allowed Values |
+=======================+=========+==========+===================+=========================================+================+
| openshift-sdn-name    | string  | Optional | n/a               | Name of the VXLAN tunnel on the BIG-IP  |                |
|                       |         |          |                   | system that corresponds to an Openshift |                |
|                       |         |          |                   | SDN HostSubnet.                         |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| flannel-name          | string  | Optional | n/a               | Name of the VXLAN tunnel on the BIG-IP  |                |
|                       |         |          |                   | system that corresponds to a Flannel    |                |
|                       |         |          |                   | subnet.                                 |                |
|                       |         |          |                   |                                         |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+

OpenShift Routes
````````````````

+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| Parameter             | Type    | Required | Default           | Description                             | Allowed Values |
+=======================+=========+==========+===================+=========================================+================+
| default-client-ssl    | string  | Optional | n/a               | Specify the name of a user created      |                |
|                       |         |          |                   | client ssl profile that will be         |                |
|                       |         |          |                   | attached to the route https vserver and |                |
|                       |         |          |                   | used as default for SNI. This profile   |                |
|                       |         |          |                   | must have the Default for SNI field     |                |
|                       |         |          |                   | enabled.                                |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| default-server-ssl    | string  | Optional | n/a               | Specify the name of a user created      |                |
|                       |         |          |                   | server ssl profile that will be         |                |
|                       |         |          |                   | attached to the route https vserver and |                |
|                       |         |          |                   | used as default for SNI. This profile   |                |
|                       |         |          |                   | must have the Default for SNI field     |                |
|                       |         |          |                   | enabled.                                |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| manage-routes         | boolean | Optional | false             | Indicates if ``k8s-bigip-ctlr`` should  | true, false    |
|                       |         |          |                   | handle OpenShift Route objects.         |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-http-vserver    | string  | Optional | ose-vserver       | The name of the http virtual server for |                |
|                       |         |          |                   | OpenShift Routes.                       |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-https-vserver   | string  | Optional | https-ose-vserver | The name of the https virtual server    |                |
|                       |         |          |                   | for OpenShift Routes.                   |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-label           | string  | Optional | n/a               | Tells the ``k8s-bigip-ctlr`` to only    |                |
|                       |         |          |                   | watch for OpenShift Route objects with  |                |
|                       |         |          |                   | the ``f5type`` label set to this value. |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-vserver-addr    | string  | Optional | n/a               | Bind address for virtual server for     |                |
|                       |         |          |                   | OpenShift Route objects.                |                |
|                       |         |          |                   |                                         |                |
|                       |         |          |                   | **Only applicable in OpenShift.**       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
  
.. note::

   If the ``default-client-ssl`` or ``default-server-ssl`` parameters are not provided, then the controller creates default
   clientssl and serverssl profiles for the OpenShift Route HTTPS virtual server. The controller sets these profiles as
   Default for SNI. 

.. _f5 resource configmap properties:

F5 Resource ConfigMap Properties
--------------------------------
F5 Resource ConfigMap objects tell the |kctlr| how to configure the BIG-IP system.
See the `Integration Overview`_ for more information about F5 resources.

+---------------+---------------------------------------------------+-----------------------------------------------+
| Property      | Description                                       | Allowed Values                                |
+===============+===================================================+===============================================+
| f5type        | Tells ``k8s-bigip-ctlr`` about resources it       |                                               |
|               | should watch                                      |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+
| schema        | Verifies the ``data`` blob                        | f5schemadb://bigip-virtual-server_v0.1.5.json |
|               |                                                   | [#schemaRecommendation]_                      |
|               |                                                   |                                               |
|               |                                                   | f5schemadb://bigip-virtual-server_v0.1.4.json |
|               |                                                   |                                               |
|               |                                                   | f5schemadb://bigip-virtual-server_v0.1.3.json |
|               |                                                   |                                               |
|               |                                                   | f5schemadb://bigip-virtual-server_v0.1.2.json |
+---------------+---------------------------------------------------+-----------------------------------------------+
| data          | Defines the F5 resource                           |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+
| frontend      | Defines object(s) created on the BIG-IP           | See :ref:`frontend`                           |
+---------------+---------------------------------------------------+-----------------------------------------------+
| backend       | Identifes the Kubernets Service acting as the     | See :ref:`backend`                            |
|               | server pool                                       |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+

.. [#schemaRecommendation] Schemas are backwards compatible. F5 recommends using the latest schema in order to make use of the new features available in the controller.

.. _frontend:

Frontend
````````
.. _virtual server f5 resource:

virtualServer
~~~~~~~~~~~~~
The ``frontend.virtualServer`` properties define BIG-IP virtual server, pool, and pool member objects.

==================== ================= ============== =========== ===================================================== ======================
Property             Type              Required       Default     Description                                           Allowed Values
==================== ================= ============== =========== ===================================================== ======================
partition            string            Required                   Define the BIG-IP partition to manage

virtualAddress       JSON object       Optional                   Allocate a virtual address from the BIG-IP

- bindAddr [#ba]_    string            Required                   Virtual IP address
- port               integer           Required                   Port number

mode                 string            Optional       tcp         Set the proxy mode                                    http, tcp, udp

balance              string            Optional       round-robin Set the load balancing mode                           round-robin

sslProfile [#ssl]_   JSON object       Optional                   BIG-IP SSL profile to apply to the virtual server.

- f5ProfileName      string            Optional                   Name of the BIG-IP SSL profile you want to use.

                                                                  Uses format :code:`partition_name/cert_name`

                                                                  Example: :code:`Common/testcert`

- f5ProfileNames     array of strings  Optional                   Array of BIG-IP SSL profile names.

                                                                  Each SSL profile name uses the format
                                                                  :code:`partition_name/cert_name`.

                                                                  Example: ::

                                                                    [
                                                                      'Common/testcert1',
                                                                      'Common/testcert2'
                                                                    ]

==================== ================= ============== =========== ===================================================== ======================

.. [#ba] The controller supports BIG-IP `route domain`_ specific addresses.
.. [#ssl] If you want to configure multiple SSL profiles, use ``f5ProfileNames`` instead of ``f5ProfileName``. The two parameters are mutually exclusive.

\

If you don't define ``bindAddr`` in the Frontend configuration, you must include it in a `Kubernetes Annotation`_ to the ConfigMap.
The Controller watches for the annotation key ``virtual-server.f5.com/ip``.
This annotation must contain the IP address you want to assign to the virtual server.

- You can `configure an IPAM system`_ to write out an annotation containing the selected IP address.
- You can check the ``status.virtual-server.f5.com/ip`` annotation set by the Controller via the Kubernetes API.
   This allows you to see the ``bindAddr`` assigned to the virtual server.

If you don't define ``virtualAddress`` or ``bindAddr`` in the Frontend configuration, the Controller configures and manages pools, pool members, and healthchecks for the Service without a BIG-IP virtual server.
In such cases, **you should already have a BIG-IP virtual server** that handles client connections configured with an iRule or local traffic policy that can forward the request to the correct pool.
The stable name of the pool will be the Kubernetes namespace the Service runs in, followed by an underscore, followed by the name of the Service's ConfigMap.
For example: :code:`default_myService`.

.. seealso::

   See `Pools without virtual servers`_ for more information.

.. _iapp f5 resource:

iApps
~~~~~

The ``frontend.virtualServer`` properties provide the information required to deploy an iApp on the BIG-IP system.

.. tip::

   The ``iappOptions`` represent information that the user would provide if deploying the iApp via the BIG-IP configuration utility.

\

==================== ================= ============== ======================================================= ====================================
Property             Type              Required       Description                                             Allowed Values
==================== ================= ============== ======================================================= ====================================
partition            string            Required       The BIG-IP partition you want the |kctlr| to manage.                                            
-------------------- ----------------- -------------- ------------------------------------------------------- ------------------------------------
iapp                 string            Required       BIG-IP iApp template to use to create the               Any iApp template that already 
                                                      application  Service.                                   exists on the BIG-IP system. 
-------------------- ----------------- -------------- ------------------------------------------------------- ------------------------------------
iappPoolMemberTable  JSON object       Required       Define the name and layout of the pool member table   
                                                      in the iApp.                                          
                                    
                                                      **See** :ref:`iApp Pool Member Table`.         
-------------------- ----------------- -------------- ------------------------------------------------------- ------------------------------------
iappTables           JSON object       Optional       Define iApp tables to apply to the Application Service
                     array
                                                      Example: ::
                                                      
                                                        "iappTables": {
                                                          "monitor__Monitors":
                                                            {"columns": ["Index", "Name", "Type", "Options"],
                                                             "rows": [[0, "mon1", "tcp", "" ],
                                                                      [1, "mon2", "http", ""]]}}"

-------------------- ----------------- -------------- ------------------------------------------------------- ------------------------------------
iappOptions          key-value object  Required       Define the App configurations                           See :ref:`configuration parameters`.        
-------------------- ----------------- -------------- ------------------------------------------------------- ------------------------------------
iappVariables        key-value object  Required       Define the iApp variables needed for Service creation.
                              
==================== ================= ============== ======================================================= ====================================

.. _iapp pool member table:

iApp Pool Member Table
^^^^^^^^^^^^^^^^^^^^^^

You can use the ``iappPoolMemberTable`` option to describe the layout of the pool-member table that the Controller should configure.  It is a JSON object with these properties:

- ``name`` (required): A string that specifies the name of the table that contains the pool members.
- ``columns`` (required): An array that specifies the columns that the Controller will configure in the pool-member table, in order.

Each entry in ``columns`` is an object that has a ``name`` property and either a ``kind`` or ``value`` property:

- ``name`` (required): A string that specifies the column name.
- ``kind``: A string that tells the Controller what property from the node to substitute.  The Controller supports ``"IPAddress"`` and ``"Port"``.
- ``value``: A string that specifies a value.  The Controller will not perform any substitution, it uses the value as specified.

For example: If you configure an application with two pods at 1.2.3.4:20123 and 1.2.3.5:20321 and you specify the following JSON::

    "iappPoolMemberTable" = {
      "name": "pool__members",
      "columns": [
        {"name": "Port", "kind": "Port"},
        {"name": "IPAddress", "kind": "IPAddress"},
        {"name": "ConnectionLimit", "value": "0"}
      ]
    }

the |kctlr| creates the table below on the BIG-IP system. ::

    {
      "name": "pool__members",
      "columnNames": [
        "Port",
        "IPAddress",
        "ConnectionLimit",
      ],
      "rows": [
        {
          "row": [
            "20123",
            "1.2.3.4",
            "0",
          ]
        },
        {
          "row": [
            "20321",
            "1.2.3.5",
            "0",
          ]
        },
      ]
    }

You will need to adjust this for the particular iApp template that you are using.  
One way to discover the format is to configure an iApp manually from a template,  then check its configuration using :command:`tmsh list sys app Service <appname>`.

.. _backend:

Backend
```````

The ``backend`` section tells the |kctlr| about the Service you want to manage.

+---------------------------+-----------+-----------+-------------+---------------------------------+---------------------------+
| Property                  | Type      | Required  | Default     | Description                     | Allowed Values            |
+===========================+===========+===========+=============+=================================+===========================+
| ServiceName               | string    | Required  | none        | The `Kubernetes Service`_       |                           |
|                           |           |           |             | representing the server pool.   |                           |
+---------------------------+-----------+-----------+-------------+---------------------------------+---------------------------+
| ServicePort               | integer   | Required  | none        | Kubernetes Service port         |                           |
|                           |           |           |             | number                          |                           |
+---------------------------+-----------+-----------+-------------+---------------------------------+---------------------------+
| healthMonitors            | JSON      | Optional  | none        | Array of TCP, UDP or HTTP       |                           |
|                           | object    |           |             | Health Monitors.                |                           |
|                           | array     |           |             |                                 |                           |
+---------------+-----------+-----------+-----------+-------------+---------------------------------+---------------------------+
|               | protocol  | string    | Required  | N/A         | Protocol used to confim health. | http, tcp, udp            |
+---------------+-----------+-----------+-----------+-------------+---------------------------------+---------------------------+
|               | interval  | integer   | Optional  | 5           | Seconds between health queries. | 1 to 86,400.              |
+---------------+-----------+-----------+-----------+-------------+---------------------------------+---------------------------+
|               | timeout   | integer   | Optional  | 16          | Seconds before query fails.     | Integer from 1 to 86,400. |
+---------------+-----------+-----------+-----------+-------------+---------------------------------+---------------------------+
|               | send      | string    | Optional  | "GET /\r\n" | HTTP request string to send.    | String values.            |
+---------------+-----------+-----------+-----------+-------------+---------------------------------+---------------------------+
|               | recv      | string    | Optional  | none        | String or RegEx pattern to      | String or valid RegEx.    |
|               |           |           |           |             | match in first 5,120 bytes of   |                           |
|               |           |           |           |             | backend response.               |                           |
+---------------+-----------+-----------+-----------+-------------+---------------------------------+---------------------------+

.. _ingress resources:

Ingress Resources
-----------------

You can use the |kctlr| as a `Kubernetes Ingress`_ Controller to `expose Services to external traffic`_.

.. _ingress annotations:

Supported annotations
`````````````````````

+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| Annotation                         | Type        | Required  | Description                                                                         | Default     |
+====================================+=============+===========+=====================================================================================+=============+
| virtual-server.f5.com/ip           | string      | Required  | The IP address you want to assign to the virtual server. Can also set the           | N/A         |
|                                    |             |           | annotation value as "controller-default" to use the ``default-ingress-ip``          |             |
|                                    |             |           | specified in the Configuration Parameters above.                                    |             |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/partition    | string      | Optional  | The BIG-IP partition in which the Controller should create/update/delete            | N/A         |
|                                    |             |           | objects for this Ingress.                                                           |             |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| kubernetes.io/ingress.class        | string      | Optional  | Tells the Controller it should only manage Ingress resources in the ``f5`` class.   | f5          |
|                                    |             |           | If defined, the value must be ``f5``.                                               |             |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/balance      | string      | Optional  | Specifies the load balancing mode.                                                  | round-robin |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/http-port    | integer     | Optional  | Specifies the HTTP port.                                                            | 80          |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/https-port   | integer     | Optional  | Specifies the HTTPS port.                                                           | 443         |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/health       | JSON object | Optional  | Defines a health monitor for the Ingress resource.                                  | N/A         |
+----------------------+-------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
|                      | path        | string      | Required  | The path for the Service specified in the Ingress resource.                         | N/A         |
|                      |             |             | [#hm1]_   |                                                                                     |             |
+----------------------+-------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
|                      | interval    | integer     | Required  | The interval at which to check the health of the virtual server.                    | N/A         |
|                      |             |             | [#hm1]_   |                                                                                     |             |
+----------------------+-------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
|                      | timeout     | integer     | Required  | Number of seconds before the check times out.                                       | N/A         |
|                      |             |             | [#hm1]_   |                                                                                     |             |
+----------------------+-------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
|                      | send        | string      | Required  | The send string to set in the health monitor. [#hm2]_                               | N/A         |
|                      |             |             | [#hm1]_   |                                                                                     |             |
+----------------------+-------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
|                      | recv        | string      | Optional  | String or RegEx pattern to match in first 5,120 bytes of backend response.          | N/A         |
+----------------------+-------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| ingress.kubernetes.io/allow-http   | boolean     | Optional  | Tells the Controller to allow HTTP traffic for HTTPS Ingress resources.             | false       |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+
| ingress.kubernetes.io/ssl-redirect | boolean     | Optional  | Tells the Controller to redirect HTTP traffic to the HTTPS port for HTTPS Ingress   | true        |
|                                    |             |           | resources (see TLS Ingress resources, below).                                       |             |
+------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+

.. _tls ingress:

TLS Ingress resources
`````````````````````

If the Ingress resource contains a `tls` section, the `allow-http` and `ssl-redirect` annotations provide a method of controlling HTTP traffic.
In this case, the Controller uses the value set in the `allow-http` annotation to enable or disable HTTP traffic.
Use the `ssl-redirect` annotation to redirect all HTTP traffic to the HTTPS Virtual Server.

You can specify one (1) or more SSL profiles in the Ingress resource.

- Profiles must already exist either in Kubernetes/OpenShift --OR-- on the BIG-IP system;

  - If the controller looks for a Kubernetes Secret with the name(s) provided first;
  - if it doesn't find a matching Secret, the Controller assumes that the name(s) matches a profile that already exists on the BIG-IP system.
  - If naming an existing BIG-IP profile, provide the full path to the profile (for example, ``/Common/clientssl``).

To configure health monitors on your Ingress resource, define the ``virtual-server.f5.com/health`` annotation with a JSON object.
Provide an array for each path specified in the Ingress resource.
For example ::

   {
   "path": "ServiceName/path",
   "send": "<send string to set in the health monitor>",
   "interval": <health check interval>,
   "timeout": <number of seconds before the check has timed out>
   }


.. _openshift routes:

OpenShift Route Resources
-------------------------

.. note::

   You can use OpenShift Route resources in an existing deployment once you `replace the OpenShift F5 Router with the BIG-IP Controller`_.

.. _supported-routes:

Supported Route Configurations
``````````````````````````````

.. important:: The |kctlr| does not support path-based routes for TLS re-encryption.

+-------------------------+-------------------+-------------------+---------+-----------------+-------------------------------------------------------------------------+
| Type                    | Client Connection | Server Connection | Path    | SSL Termination | Description                                                             |
|                         | Encrypted         | Encrypted         | Support | on BIG-IP       |                                                                         |
+=========================+===================+===================+=========+=================+=========================================================================+
| Unsecured               | No                | No                | Yes     | No              | The BIG-IP system forwards unsecured traffic from the client to the     |
|                         |                   |                   |         |                 | endpoint.                                                               |
+-------------------------+-------------------+-------------------+---------+-----------------+-------------------------------------------------------------------------+
| Edge Terminated         | Yes               | No                | Yes     | Yes             | The Controller maintains a new client SSL profile on the BIG-IP system  |
|                         |                   |                   |         |                 | based on the client certificate and key from the Route resource.        |
|                         |                   |                   |         |                 |                                                                         |
|                         |                   |                   |         |                 | - Set `insecureEdgeTerminationPolicy` in the Route resource to `Allow`  |
|                         |                   |                   |         |                 |   to enable support for insecure client connections.                    |
|                         |                   |                   |         |                 |                                                                         |
|                         |                   |                   |         |                 | - Set `insecureEdgeTerminationPolicy` in the Route resource to          |
|                         |                   |                   |         |                 |   `Redirect` to redirect HTTP client connections to the HTTPS endpoint. |
+-------------------------+-------------------+-------------------+---------+-----------------+-------------------------------------------------------------------------+
| Passthrough Terminated  | Yes               | Yes               | No      | No              | The BIG-IP system uses an iRule to select the destination pool based on |
|                         |                   |                   |         |                 | SNI and forward the re-encrypted traffic.                               |
+-------------------------+-------------------+-------------------+---------+-----------------+-------------------------------------------------------------------------+
| Re-encrypt Terminated   | Yes               | Yes               | Yes     | Yes             | The Controller maintains a new BIG-IP client SSL profile based          |
|                         |                   |                   |         |                 | on the client certificate and key from the Route resource.              |
|                         |                   |                   |         |                 |                                                                         |
|                         |                   |                   |         |                 | The Controller maintains a new BIG-IP server SSL profile based          |
|                         |                   |                   |         |                 | on the server CA certificate from the Route resource for re-encrypting  |
|                         |                   |                   |         |                 | the traffic.                                                            |
|                         |                   |                   |         |                 |                                                                         |
|                         |                   |                   |         |                 | The BIG-IP system uses an iRule to select the destination pool based on |
|                         |                   |                   |         |                 | SNI and forward the re-encrypted traffic.                               |
+-------------------------+-------------------+-------------------+---------+-----------------+-------------------------------------------------------------------------+


Supported Route Annotations
```````````````````````````

+----------------------------------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
| Annotation                             | Type        | Required  | Description                                                                    | Default     |
+========================================+=============+===========+================================================================================+=============+
| virtual-server.f5.com/balance          | string      | Optional  | Specifies the load balancing mode.                                             | round-robin |
+----------------------------------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/clientssl        | string      | Optional  | The name of a pre-configured client ssl profile on the BIG-IP system.          | N/A         |
|                                        |             |           | The controller uses this profile instead of the certificate and key within the |             |
|                                        |             |           | Route's configuration.                                                         |             |
+----------------------------------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/serverssl        | string      | Optional  | The name of a pre-configured server ssl profile on the BIG-IP system.          | N/A         |
|                                        |             |           | The controller uses this profile instead of the certificate within the         |             |
|                                        |             |           | Route's configuration.                                                         |             |
+----------------------------------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/health           | JSON object | Optional  | Defines a health monitor for the Route resource.                               | N/A         |
+----------------------+-----------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
|                      | path            | string      | Required  | The path for the Service specified in the Route resource.                      | N/A         |
|                      |                 |             | [#hm1]_   |                                                                                |             |
+----------------------+-----------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
|                      | interval        | integer     | Required  | The interval at which to check the health of the virtual server.               | N/A         |
|                      |                 |             | [#hm1]_   |                                                                                |             |
+----------------------+-----------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
|                      | timeout         | integer     | Required  | Number of seconds before the check times out.                                  | N/A         |
|                      |                 |             | [#hm1]_   |                                                                                |             |
+----------------------+-----------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
|                      | send            | string      | Required  | The send string to set in the health monitor. [#hm2]_                          | N/A         |
|                      |                 |             | [#hm1]_   |                                                                                |             |
+----------------------+-----------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
|                      | recv            | string      | Optional  | String or RegEx pattern to match in first 5,120 bytes of backend response.     | N/A         |
+----------------------+-----------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+
| virtual-server.f5.com/secure-serverssl | boolean     | Optional  | Specify to validate the server-side SSL certificate of re-encrypt              | false       |
|                                        |             |           | terminated routes.                                                             |             |
+----------------------------------------+-------------+-----------+--------------------------------------------------------------------------------+-------------+

Please see the example configuration files for more details.

Example Configuration Files
---------------------------

- :fonticon:`fa fa-download` :download:`sample-k8s-bigip-ctlr-secrets.yaml </_static/config_examples/sample-k8s-bigip-ctlr-secrets.yaml>`
- :fonticon:`fa fa-download` :download:`sample-bigip-credentials-secret.yaml </_static/config_examples/sample-bigip-credentials-secret.yaml>`
- :fonticon:`fa fa-download` :download:`example-vs-resource.configmap.yaml </_static/config_examples/example-vs-resource.configmap.yaml>`
- :fonticon:`fa fa-download` :download:`example-vs-resource-udp.configmap.yaml </_static/config_examples/example-vs-resource-udp.configmap.yaml>`
- :fonticon:`fa fa-download` :download:`example-vs-resource.json </_static/config_examples/example-vs-resource.json>`
- :fonticon:`fa fa-download` :download:`example-vs-resource-iapp.json </_static/config_examples/example-vs-resource-iapp.json>`
- :fonticon:`fa fa-download` :download:`example-advanced-vs-resource-iapp.json </_static/config_examples/example-advanced-vs-resource-iapp.json>`
- :fonticon:`fa fa-download` :download:`single-service-ingress.yaml </_static/config_examples/single-service-ingress.yaml>`
- :fonticon:`fa fa-download` :download:`single-service-tls-ingress.yaml </_static/config_examples/single-service-tls-ingress.yaml>`
- :fonticon:`fa fa-download` :download:`simple-ingress-fanout.yaml </_static/config_examples/simple-ingress-fanout.yaml>`
- :fonticon:`fa fa-download` :download:`name-based-ingress.yaml </_static/config_examples/name-based-ingress.yaml>`
- :fonticon:`fa fa-download` :download:`ingress-with-health-monitors.yaml </_static/config_examples/ingress-with-health-monitors.yaml>`
- :fonticon:`fa fa-download` :download:`sample-rbac.yaml </_static/config_examples/sample-rbac.yaml>`
- :fonticon:`fa fa-download` :download:`sample-unsecured-route.yaml </_static/config_examples/sample-unsecured-route.yaml>`
- :fonticon:`fa fa-download` :download:`sample-edge-route.yaml </_static/config_examples/sample-edge-route.yaml>`
- :fonticon:`fa fa-download` :download:`sample-passthrough-route.yaml </_static/config_examples/sample-passthrough-route.yaml>`
- :fonticon:`fa fa-download` :download:`sample-reencrypt-route.yaml </_static/config_examples/sample-reencrypt-route.yaml>`

.. rubric:: Footnotes
.. [#objectpartition] The |kctlr| creates and manages objects in the BIG-IP partition defined in the `F5 resource`_ ConfigMap. **It cannot manage objects in the** ``/Common`` **partition**.
.. [#nodeportmode] The |kctlr| forwards traffic to the NodePort assigned to the Service by Kubernetes. See the `Kubernetes Service`_ documentation for more information.
.. [#secrets] You can `secure your BIG-IP credentials`_ using a Kubernetes Secret.
.. [#username] The BIG-IP user account must have an appropriate role defined.  For ``nodeport`` type pool members, this role must be either ``Administrator``, ``Resource Administrator``, or ``Manager``. For ``cluster`` type pool members, the user account must have either the ``Administrator`` or ``Resource Manager`` role. See `BIG-IP Users <https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/tmos-concepts-11-5-0/10.html>`_ for further details.
.. [#hm1] Required if defining the ``virtual-server.f5.com/health`` Ingress/Route annotation.
.. [#hm2] See the **HTTP monitor settings** section of the `BIG-IP LTM Monitors Reference Guide <https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-local-traffic-manager-monitors-reference-13-0-0/3.html>`_ for more information about defining send strings.

.. |Slack| image:: https://f5cloudsolutions.herokuapp.com/badge.svg
   :target: https://f5cloudsolutions.herokuapp.com
   :alt: Slack
