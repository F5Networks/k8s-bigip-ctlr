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
- Support for `F5 AS3 Extension`_ declarations.
- Support for F5 `iApps`_.
- Handles F5-specific VirtualServer objects created in Kubernetes.
- Handles standard `Kubernetes Ingress`_ objects using F5-specific extensions.
- Handles OpenShift Route objects using F5-specific extensions.

Guides
------
See the |kctlr-long| `user documentation`_.

Installation
------------
- `Kubernetes Installation`_
- `F5 AS3 Installation`_
- `OpenShift Installation`_
- If you use `helm`_ you can install the |kctlr| using the `f5-bigip-ctlr chart`_.

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

   F5 does not recommend making configuration changes to objects in any partition managed by the |kctlr| via any other means (for example, the configuration utility, TMOS, or by syncing configuration with another device or service group). Doing so may result in disruption of service or unexpected behavior.

   The Controller allows one exception to this recommendation.  When using named virtual servers for :ref:`Openshift routes <openshift route configs>`, you can set the Controller to merge its desired settings with a pre-existing virtual server(s). See `Manage OpenShift Routes`_ for more information.

.. _configuration parameters:

Controller Configuration Parameters
-----------------------------------

All of the configuration parameters below are global.

.. _general configs:

General
```````

+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+
| Parameter             | Type    | Required | Default                          | Description                                  | Allowed Values |
+=======================+=========+==========+==================================+==============================================+================+
| http-listen-address   | string  | Optional | "0.0.0.0:8080"                   | Address at which to serve HTTP-based         |                |
|                       |         |          |                                  | information (for example, ``/metrics``,      |                |
|                       |         |          |                                  | ``health``) to `Prometheus`_                 |                |
|                       |         |          |                                  |                                              |                |
|                       |         |          |                                  | :fonticon:`fa fa-flask` Beta feature         |                |
+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+
| log-level             | string  | Optional | INFO                             | Log level                                    | INFO,          |
|                       |         |          |                                  |                                              | DEBUG,         |
|                       |         |          |                                  |                                              | CRITICAL,      |
|                       |         |          |                                  |                                              | WARNING,       |
|                       |         |          |                                  |                                              | ERROR          |
+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+
| node-poll-interval    | integer | Optional | 30                               | In seconds, the interval at which the        |                |
|                       |         |          |                                  | |kctlr| polls the cluster to find all        |                |
|                       |         |          |                                  | node members.                                |                |
+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+
| python-basedir        | string  | Optional | /app/python                      | Path to the python utilities                 |                |
|                       |         |          |                                  | directory                                    |                |
+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+
| schema-db-base-dir    | string  | Optional |file:///app/vendor/src/f5/schemas | Path to the directory containing the         |                |
|                       |         |          |                                  | F5 schema db                                 |                |
+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+
| verify-interval       | integer | n/a      | 30                               | In seconds, the interval at which the        |                |
|                       |         |          |                                  | |kctlr| verifies that the BIG-IP             |                |
|                       |         |          |                                  | configuration matches the state of           |                |
|                       |         |          |                                  | the orchestration system.                    |                |
|                       |         |          |                                  |                                              |                |
|                       |         |          |                                  | **This value is not currently configurable** |                |
+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+
| vs-snat-pool-name     | string  | Optional | n/a                              | Name of the SNAT pool that all virtual       |                |
|                       |         |          |                                  | servers will reference. If it is not         |                |
|                       |         |          |                                  | set, virtual servers use automap SNAT.       |                |
+-----------------------+---------+----------+----------------------------------+----------------------------------------------+----------------+

.. note::

   - The :code:`python-basedir` setting lets you specify the path to an alternate python agent that can bridge between the |kctlr| and `F5 CCCL <https://github.com/f5devcentral/f5-cccl>`_.

   - The time it takes for the |kctlr| to reapply the system configurations to the BIG-IP device is normally low (a few ms) and won't cause service disruption. 

   - Use :code:`vs-snat-pool-name` if you want virtual servers to reference a SNAT pool that already exists in the :code:`/Common` partition on the BIG-IP device.
     See `Overview of SNAT features`_ on AskF5 for more information.

.. _bigip configs:

BIG-IP system
`````````````

+-----------------------+---------+----------+-------------------+--------------------------------------------+----------------+
| Parameter             | Type    | Required | Default           | Description                                | Allowed Values |
+=======================+=========+==========+===================+============================================+================+
| bigip-partition       | string  | Required | n/a               | The BIG-IP partition in which              |                |
|                       |         |          |                   | to configure objects.                      |                |
+-----------------------+---------+----------+-------------------+--------------------------------------------+----------------+
| bigip-password        | string  | Required | n/a               | BIG-IP iControl REST password              |                |
|                       |         |          |                   |                                            |                |
|                       |         |          |                   | You can `secure your BIG-IP credentials`_  |                |
|                       |         |          |                   | using a Kubernetes Secret.                 |                |
+-----------------------+---------+----------+-------------------+--------------------------------------------+----------------+
| bigip-url             | string  | Required | n/a               | BIG-IP admin IP address                    |                |
+-----------------------+---------+----------+-------------------+--------------------------------------------+----------------+
| bigip-username        | string  | Required | n/a               | BIG-IP iControl REST username              |                |
|                       |         |          |                   |                                            |                |
|                       |         |          |                   | The BIG-IP user account must have the      |                |
|                       |         |          |                   | appropriate role defined:                  |                |
|                       |         |          |                   |                                            |                |
|                       |         |          |                   | For ``nodeport`` type pool members, the    |                |
|                       |         |          |                   | role must be ``Administrator``.            |                |
|                       |         |          |                   |                                            |                |
|                       |         |          |                   | For ``cluster`` type pool members, the     |                |
|                       |         |          |                   | role must be ``Administrator``.            |                |
+-----------------------+---------+----------+-------------------+--------------------------------------------+----------------+
| credentials-directory | string  | Optional | n/a               | Directory that contains the BIG-IP         |                |
|                       |         |          |                   | username, password, or url files           |                |
+-----------------------+---------+----------+-------------------+--------------------------------------------+----------------+

.. important::

     The :code:`credentials-directory` option is an alternative to using the :code:`bigip-username`, :code:`bigip-password`, or
     :code:`bigip-url` arguments.

     When you use this argument, the controller looks for three files in the specified directory:

     - "username", "password", and "url"

     If any of these files do not exist, the controller falls back to using the CLI arguments as parameters.

     Each file should contain **only** the username, password, and url, respectively. You can create and mount
     the files as `Kubernetes Secrets`_.
     
     It is important to not project the Secret keys to specific paths, as the controller looks for the "username",
     "password", and "url" files directly within the credentials directory.

     See :fonticon:`fa fa-download` :download:`example-bigip-credentials-directory.yaml </_static/config_examples/example-bigip-credentials-directory.yaml>`
     for a deployment example.

.. _vxlan configs:

VXLAN
`````

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

.. _k8s configs:

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
| manage-configmaps     | boolean | Optional | true              | Tells the controller whether or not     | true, false    |
|                       |         |          |                   | to watch Kubernetes ConfigMaps and      |                |
|                       |         |          |                   | apply their configuration.              |                |
|                       |         |          |                   | If false, the controller will ignore    |                |
|                       |         |          |                   | ConfigMap events.                       |                |
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
|                       |         |          |                   | to create.                              | nodeport       |
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

.. _openshift route configs:

OpenShift Routes
````````````````

**The following configuration parameters only apply to OpenShift.**

+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| Parameter             | Type    | Required | Default           | Description                             | Allowed Values |
+=======================+=========+==========+===================+=========================================+================+
| custom-client-ssl     | string  | Optional | n/a               | Specifies the name of a custom          |                |
|                       |         |          |                   | client SSL profile attached to the      |                |
|                       |         |          |                   | route HTTPS virtual server and          |                |
|                       |         |          |                   | used as default for SNI. This profile   |                |
|                       |         |          |                   | must have the Default for SNI field     |                |
|                       |         |          |                   | enabled.                                |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| custom-server-ssl     | string  | Optional | n/a               | Specifies the name of a custom          |                |
|                       |         |          |                   | server SSL profile attached to the      |                |
|                       |         |          |                   | route HTTPS virtual server and          |                |
|                       |         |          |                   | used as default for SNI. This profile   |                |
|                       |         |          |                   | must have the Default for SNI field     |                |
|                       |         |          |                   | enabled.                                |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| manage-routes         | boolean | Optional | false             | Indicates if ``k8s-bigip-ctlr`` should  | true, false    |
|                       |         |          |                   | handle OpenShift Route objects.         |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-http-vserver    | string  | Optional | ose-vserver       | The name of the http virtual server for |                |
|                       |         |          |                   | OpenShift Routes.                       |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-https-vserver   | string  | Optional | https-ose-vserver | The name of the https virtual server    |                |
|                       |         |          |                   | for OpenShift Routes.                   |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-label           | string  | Optional | n/a               | Tells the ``k8s-bigip-ctlr`` to only    |                |
|                       |         |          |                   | watch for OpenShift Route objects with  |                |
|                       |         |          |                   | the ``f5type`` label set to this value. |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+
| route-vserver-addr    | string  | Optional | n/a               | Bind address for virtual server for     |                |
|                       |         |          |                   | OpenShift Route objects.                |                |
+-----------------------+---------+----------+-------------------+-----------------------------------------+----------------+

.. note::

   If the ``custom-client-ssl`` or ``custom-server-ssl`` parameters are not provided, then the controller creates default
   clientssl and serverssl profiles for the OpenShift Route HTTPS virtual server. The controller sets these profiles as
   Default for SNI.

- :fonticon:`fa fa-download` :download:`example-openshift-custom-ssl-profile.yaml </_static/config_examples/example-openshift-custom-ssl-profile.yaml>`
- :fonticon:`fa fa-download` :download:`example-openshift-default-ssl-profile.yaml </_static/config_examples/example-openshift-default-ssl-profile.yaml>`

.. _f5 resource configmap properties:

F5 Resource ConfigMap Properties
--------------------------------

F5 Resource ConfigMap objects tell the |kctlr| how to configure the BIG-IP system.
See the `Integration Overview`_ for more information about F5 resources.

.. note::

   The Controller uses the following naming structure when creating BIG-IP objects:

   ``<service-namespace>_<configmap-name>``

   For a Service named "myService" running in the "default" namespace, the Controller would create a BIG-IP pool with the following name:

   ``default_myService``


+---------------+---------------------------------------------------+-----------------------------------------------+
| Property      | Description                                       | Allowed Values                                |
+===============+===================================================+===============================================+
| f5type        | Tells ``k8s-bigip-ctlr`` about resources it       |                                               |
|               | should watch                                      |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+
| schema        | Verifies the ``data`` blob                        | See the `F5 schema versions`_ table           |
+---------------+---------------------------------------------------+-----------------------------------------------+
| data          | Defines the F5 resource                           |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+
| frontend      | Defines BIG-IP objects                            | See :ref:`frontend`                           |
+---------------+---------------------------------------------------+-----------------------------------------------+
| backend       | Identifies the Kubernetes Service acting as the   | See :ref:`backend`                            |
|               | server pool                                       |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+


F5 schema
`````````

The `F5 schema`_ allows the |kctlr| to communicate with BIG-IP systems.

.. note::

   While all versions of the BIG-IP Controller and F5 schema are backwards-compatible, using an older schema may limit Controller functionality. Be sure to use the schema version that corresponds with your Controller version to ensure access to the full feature set.

   See the `F5 schema versions`_ table for schema and Controller version compatibility.

.. _frontend:

Frontend
````````

.. _virtual server f5 resource:

Virtual Servers
~~~~~~~~~~~~~~~

Use the options shown in the table below in the ``frontend`` section of an F5 resource ConfigMap to define BIG-IP virtual server(s), pool(s), and pool member(s).

========================== ================= ============== =========== =============================================================== ===============================================
Property                   Type              Required       Default     Description                                                     Allowed Values
========================== ================= ============== =========== =============================================================== ===============================================
partition                  string            Required                   The BIG-IP partition you want to manage
-------------------------- ----------------- -------------- ----------- --------------------------------------------------------------- -----------------------------------------------
virtualAddress             JSON object       Optional                   Assigns a BIG-IP self IP to the virtual server

- bindAddr [#ba]_          string            Required                   Virtual IP address
- port                     integer           Required                   Port number
-------------------------- ----------------- -------------- ----------- --------------------------------------------------------------- -----------------------------------------------
mode                       string            Optional       tcp         Sets the proxy mode                                             http, tcp, udp
-------------------------- ----------------- -------------- ----------- --------------------------------------------------------------- -----------------------------------------------
.. _balance:

balance                    string            Optional       round-robin Sets the load balancing mode                                    Any supported load balancing algorithm [#lb]_
-------------------------- ----------------- -------------- ----------- --------------------------------------------------------------- -----------------------------------------------
sslProfile [#ssl]_         JSON object       Optional                   BIG-IP SSL profile to apply to the virtual server.

- f5ProfileName            string            Optional                   Name of the BIG-IP SSL profile you want to use.

                                                                        Uses format :code:`partition_name/cert_name`

                                                                        Example: :code:`Common/testcert`

- f5ProfileNames           array of strings  Optional                   Array of BIG-IP SSL profile names.

                                                                        Each SSL profile name uses the format
                                                                        :code:`partition_name/cert_name`.

                                                                        Example: ::

                                                                          [
                                                                            'Common/testcert1',
                                                                            'Common/testcert2'
                                                                          ]

========================== ================= ============== =========== =============================================================== ===============================================


.. note::

   If you include ``virtualAddress`` in your Resource definition, you can specify the ``bindAddr`` and ``port`` you want the virtual server to use. Omit the ``virtualAddress`` section if you want to create `pools without virtual servers`_.

   If you're creating pools without virtual servers, **you should already have a BIG-IP virtual server** that handles client connections configured with an iRule or local traffic policy that can forward requests to the correct pool for the Service.

   You can also `assign IP addresses to BIG-IP virtual servers using IPAM`_.

.. _iapp f5 resource:

iApps
~~~~~

Use the options shown in the table below in the ``frontend`` section of an F5 resource ConfigMap to deploy an iApp on the BIG-IP system.

.. tip::

   The ``iappOptions`` parameter should contain the information that you would provide if you deployed the iApp using the BIG-IP configuration utility.

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
iappOptions          key-value object  Required       Define the App configurations                           Varies
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

.. _as3 resources:

F5 AS3 Integration Resources
----------------------------

To expose services to external traffic using As3 Extension declarations, refer to `Container Ingress Services and AS3 Extension integration`_.

.. _ingress resources:

Kubernetes Ingress Resources
----------------------------

You can use the |kctlr| to `Expose Services to External Traffic using Ingresses`_.

.. _ingress annotations:

Supported Ingress Annotations
`````````````````````````````

+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| Annotation                                    | Type        | Required  | Description                                                                         | Default     | Allowed Values                          |
+===============================================+=============+===========+=====================================================================================+=============+=========================================+
| virtual-server.f5.com/ip                      | string      | Required  | The IP address you want to assign to the virtual server.                            | N/A         | numerical IP address                    |
|                                               |             |           |                                                                                     |             |                                         |
|                                               |             |           | Set to "controller-default" if you want to use the ``default-ingress-ip``           |             |                                         |
|                                               |             |           | specified in the Configuration Parameters above.                                    |             | "controller-default"                    |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/partition               | string      | Optional  | The BIG-IP partition in which the Controller should create/update/delete            | N/A         |                                         |
|                                               |             |           | objects for this Ingress.                                                           |             |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| kubernetes.io/ingress.class                   | string      | Optional  | Tells the Controller it should only manage Ingress resources in the ``f5`` class.   | f5          | "f5"                                    |
|                                               |             |           | If defined, the value must be ``f5``.                                               |             |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/balance                 | string      | Optional  | Sets the load balancing mode.                                                       | round-robin | Any supported                           |
|                                               |             |           |                                                                                     |             | load balancing algorithm [#lb]_         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/http-port               | integer     | Optional  | Specifies the HTTP port.                                                            | 80          |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/https-port              | integer     | Optional  | Specifies the HTTPS port.                                                           | 443         |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/health                  | JSON object | Optional  | Defines a health monitor for the Ingress resource.                                  | N/A         |                                         |
+----+------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | path                                     | string      | Required  | The path for the Service specified in the Ingress resource.                         | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                     |             |                                         |
+----+------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | interval                                 | integer     | Required  | The interval at which to check the health of the virtual server.                    | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                     |             |                                         |
+----+------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | timeout                                  | integer     | Required  | Number of seconds before the check times out.                                       | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                     |             |                                         |
+----+------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | send                                     | string      | Required  | The send string to set in the health monitor. [#hm2]_                               | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                     |             |                                         |
+----+------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | recv                                     | string      | Optional  | String or RegEx pattern to match in first 5,120 bytes of backend response.          | N/A         |                                         |
+----+------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | type                                     | string      | Optional  | Health monitor type. Typically http or https.                                       | http        |                                         |
+----+------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| ingress.kubernetes.io/allow-http              | boolean     | Optional  | Tells the Controller to allow HTTP traffic for HTTPS Ingress resources.             | false       | "true", "false"                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| ingress.kubernetes.io/ssl-redirect            | boolean     | Optional  | Tells the Controller to redirect HTTP traffic to the HTTPS port for HTTPS Ingress   | true        | "true", "false"                         |
|                                               |             |           | resources (see TLS Ingress resources, below).                                       |             |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/serverssl               | string      | Optional  | The name of a pre-configured server ssl profile on the BIG-IP system.               | N/A         |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/rewrite-app-root        | string      | Optional  | Root path redirection for the application.                                          | N/A         |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/rewrite-target-url      | string      | Optional  | URL host, path, or host and path to be rewritten.                                   | N/A         |                                         |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/whitelist-source-range  | string      | Optional  | Comma separated list of CIDR addresses to allow inbound to Ingress services.        | N/A         | Comma separated, CIDR formatted, IP     |
|                                               |             |           |                                                                                     |             | addresses.                              |
|                                               |             |           |                                                                                     |             |                                         |
|                                               |             |           |                                                                                     |             | ex. 1.2.3.4/32,2.2.2.0/24               |
+-----------------------------------------------+-------------+-----------+-------------------------------------------------------------------------------------+-------------+-----------------------------------------+

Ingress Health Monitors
```````````````````````

To configure health monitors on your Ingress resource, define the ``virtual-server.f5.com/health`` annotation with a JSON object.
Provide an array for each path specified in the Ingress resource.

For example ::

   {
   "path": "ServiceName/path",
   "send": "<send string to set in the health monitor>",
   "interval": <health check interval>,
   "timeout": <number of seconds before the check has timed out>
   }

.. _tls ingress:

TLS Ingress Resources
`````````````````````

If the Ingress resource contains a `tls` section, the `allow-http` and `ssl-redirect` annotations provide a method of controlling HTTP traffic.
In this case, the Controller uses the value set in the `allow-http` annotation to enable or disable HTTP traffic.
Use the `ssl-redirect` annotation to redirect all HTTP traffic to the HTTPS Virtual Server.

You can specify one (1) or more SSL profiles in the Ingress resource.

- Profiles must already exist either in Kubernetes/OpenShift --OR-- on the BIG-IP system;

  - If the controller looks for a Kubernetes Secret with the name(s) provided first;
  - if it doesn't find a matching Secret, the Controller assumes that the name(s) matches a profile that already exists on the BIG-IP system.
  - If naming an existing BIG-IP profile, provide the full path to the profile (for example, ``/Common/clientssl``).

.. _openshift routes:

OpenShift Route Resources
-------------------------

.. note::

   You can use OpenShift Route resources in an existing deployment once you `replace the OpenShift F5 Router with the BIG-IP Controller`_.

.. _supported-routes:

Supported Route Configurations
``````````````````````````````

.. important:: The |kctlr| supports a single path-based route for TLS re-encryption. Multiple path-based routes are not currently supported.

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

.. _route annotations:

Supported Route Annotations
```````````````````````````

+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| Annotation                                    | Type        | Required  | Description                                                                       | Default     | Allowed Values                          |
+===============================================+=============+===========+===================================================================================+=============+=========================================+
| virtual-server.f5.com/balance                 | string      | Optional  | Sets the load balancing mode.                                                     | round-robin | Any supported                           |
|                                               |             |           |                                                                                   |             | load balancing algorithm [#lb]_         |
+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/clientssl               | string      | Optional  | The name of a pre-configured client ssl profile on the BIG-IP system.             | N/A         |                                         |
|                                               |             |           | The controller uses this profile instead of the certificate and key within the    |             |                                         |
|                                               |             |           | Route's configuration.                                                            |             |                                         |
+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/serverssl               | string      | Optional  | The name of a pre-configured server ssl profile on the BIG-IP system.             | N/A         |                                         |
|                                               |             |           | The controller uses this profile instead of the certificate within the            |             |                                         |
|                                               |             |           | Route's configuration.                                                            |             |                                         |
+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/health                  | JSON object | Optional  | Defines a health monitor for the Route resource.                                  | N/A         |                                         |
+----+------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | path                                     | string      | Required  | The path for the Service specified in the Route resource.                         | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                   |             |                                         |
+----+------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | interval                                 | integer     | Required  | The interval at which to check the health of the virtual server.                  | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                   |             |                                         |
+----+------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | timeout                                  | integer     | Required  | Number of seconds before the check times out.                                     | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                   |             |                                         |
+----+------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | send                                     | string      | Required  | The send string to set in the health monitor. [#hm2]_                             | N/A         |                                         |
|    |                                          |             | [#hm1]_   |                                                                                   |             |                                         |
+----+------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
|    | recv                                     | string      | Optional  | String or RegEx pattern to match in first 5,120 bytes of backend response.        | N/A         |                                         |
+----+------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/secure-serverssl        | boolean     | Optional  | Specify to validate the server-side SSL certificate of re-encrypt                 | false       | "true", "false"                         |
|                                               |             |           | terminated routes.                                                                |             |                                         |
+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/rewrite-app-root        | string      | Optional  | Root path redirection for the application.                                        | N/A         |                                         |
+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/rewrite-target-url      | string      | Optional  | URL host, path, or host and path to be rewritten.                                 | N/A         |                                         |
+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+
| virtual-server.f5.com/whitelist-source-range  | string      | Optional  | Comma separated list of CIDR addresses to allow inbound to Route services.        | N/A         | Comma separated, CIDR formatted, IP     |
|                                               |             |           |                                                                                   |             | addresses.                              |
|                                               |             |           |                                                                                   |             |                                         |
|                                               |             |           |                                                                                   |             | ex. 1.2.3.4/32,2.2.2.0/24               |
+-----------------------------------------------+-------------+-----------+-----------------------------------------------------------------------------------+-------------+-----------------------------------------+

.. important::

    For edge (client) termination, a Route **must** include **either** the certificate/key literal information
    in the Route Spec, **or** the clientssl annotation. For re-encrypt (server) termination, a Route **must** include
    **either** the destinationCaCertificate literal information in the Route Spec, **or** the serverssl annotation, 
    in addition to the edge rules listed previously. If you want to use the configuration parameters 
    `default-clientssl` or `default-serverssl` profiles for a Route, then specify those profile names in the
    Route annotations in addition to the controller configuration.

Please see the example configuration files for more details.

.. _conf examples:

Example Configuration Files
---------------------------

- :fonticon:`fa fa-download` :download:`sample-k8s-bigip-ctlr-secrets.yaml </_static/config_examples/sample-k8s-bigip-ctlr-secrets.yaml>`
- :fonticon:`fa fa-download` :download:`sample-bigip-credentials-secret.yaml </_static/config_examples/sample-bigip-credentials-secret.yaml>`
- :fonticon:`fa fa-download` :download:`example-bigip-credentials-directory.yaml </_static/config_examples/example-bigip-credentials-directory.yaml>`
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
- :fonticon:`fa fa-download` :download:`sample-app-root-annotation.yaml </_static/config_examples/sample-app-root-annotation.yaml>`
- :fonticon:`fa fa-download` :download:`sample-url-rewrite-annotation.yaml </_static/config_examples/sample-url-rewrite-annotation.yaml>`

OpenShift
`````````

- :fonticon:`fa fa-download` :download:`sample-unsecured-route.yaml </_static/config_examples/sample-unsecured-route.yaml>`
- :fonticon:`fa fa-download` :download:`sample-edge-route.yaml </_static/config_examples/sample-edge-route.yaml>`
- :fonticon:`fa fa-download` :download:`sample-passthrough-route.yaml </_static/config_examples/sample-passthrough-route.yaml>`
- :fonticon:`fa fa-download` :download:`sample-reencrypt-route.yaml </_static/config_examples/sample-reencrypt-route.yaml>`



.. rubric:: **Footnotes**
.. [#objectpartition] The |kctlr| creates and manages objects in the BIG-IP partition defined in the `F5 resource`_ ConfigMap. **It cannot manage objects in the** ``/Common`` **partition**.
.. [#nodeportmode] The |kctlr| forwards traffic to the NodePort assigned to the Service by Kubernetes. See the `Kubernetes Service`_ documentation for more information.
.. [#lb] The |kctlr| supports BIG-IP load balancing algorithms that do not require additional configuration parameters. You can view the full list of supported algorithms in the `f5-cccl schema <https://github.com/f5devcentral/f5-cccl/blob/03e22c4779ceb88f529337ade3ca31ddcd57e4c8/f5_cccl/schemas/cccl-ltm-api-schema.yml#L515>`_. See the `BIG-IP Local Traffic Management Basics user guide <https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-basics-13-0-0/4.html>`_ for information about each load balancing mode.
.. [#ba] The Controller supports BIG-IP `route domain`_ specific addresses.
.. [#ssl] If you want to configure multiple SSL profiles, use ``f5ProfileNames`` instead of ``f5ProfileName``. The two parameters are mutually exclusive.
.. [#hm1] Required if defining the ``virtual-server.f5.com/health`` Ingress/Route annotation.
.. [#hm2] See the **HTTP monitor settings** section of the `BIG-IP LTM Monitors Reference Guide <https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-local-traffic-manager-monitors-reference-13-0-0/3.html>`_ for more information about defining send strings.

.. |Slack| image:: https://f5cloudsolutions.herokuapp.com/badge.svg
   :target: https://f5cloudsolutions.herokuapp.com
   :alt: Slack
.. _loadBalancingMode options in f5-cccl: https://github.com/f5devcentral/f5-cccl/blob/master/f5_cccl/schemas/cccl-ltm-api-schema.yml
.. _Prometheus: https://prometheus.io/
