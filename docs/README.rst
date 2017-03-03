F5 Kubernetes BIG-IP Controller
===============================

.. toctree::
    :hidden:
    :maxdepth: 2


F5 Kubernetes BIG-IP Controller manages F5 BIG-IP `Local Traffic Manager <https://f5.com/products/big-ip/local-traffic-manager-ltm>`_ (LTM) objects from `Kubernetes`_.
See the `F5 Kubernetes BIG-IP Controller documentation <#tbd>`_ for user guides, tutorials, and more.


Features
--------
- Dynamically creates, manages, and destroys BIG-IP objects.
- Forwards traffic from BIG-IP to `Kubernetes clusters`_ via `NodePorts`_.
- Uses existing BIG-IP SSL profiles for authentication.
- Support for F5 `iApps`_.

Guides
------

Getting Started
```````````````
- links
- to
- guides

Deployment
``````````
- links
- to
- guides

Troubleshooting
```````````````
- coming soon!

Architecture
------------

F5 Kubernetes BIG-IP Controller is a Docker container that runs in a `Kubernetes`_ Pod.
It uses an `F5 Resource`_ to determine:

- what objects to configure on your BIG-IP, and
- to which `Kubernetes Service`_ the BIG-IP objects belong.

The F5 Kubernetes BIG-IP Controller watches the Kubernetes API for the creation and modification of F5 resources.
When it discovers changes, the F5 Kubernetes BIG-IP Controller modifies the BIG-IP accordingly.


For example:

#. F5 Kubernetes BIG-IP Controller discovers a new F5 ``virtualServer`` resource.
#. F5 Kubernetes BIG-IP Controller creates a new virtual server object on the BIG-IP; [#objectpartition]_
#. F5 Kubernetes BIG-IP Controller creates a pool member on the virtual server for each node in the cluster; [#nodeport]_
#. F5 Kubernetes BIG-IP Controller monitors F5 resources, and linked Kubernetes resources, for changes.
#. F5 Kubernetes BIG-IP Controller reconfigures the BIG-IP when it discovers changes.

The BIG-IP handles traffic for the Service the specified virtual address and load-balances to all nodes in the cluster. Within the cluster, the allocated NodePort load balances traffic to all pods.

Configuration Parameters
------------------------

+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| Parameter          | Type      | Required  | Default       | Description                   | Allowed Values    |
+====================+===========+===========+===============+===============================+===================+
| bigip-username     | string    | Required  | n/a           | BIG-IP account username       |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| bigip-password     | string    | Required  | n/a           | BIG-IP account password       |                   |
|                    |           |           |               | [#secrets]_                   |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| bigip-url          | string    | Required  | n/a           | BIG-IP admin IP address       |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| bigip-partition    | string    | Required  | n/a           | The BIG-IP partition in which |                   |
|                    |           |           |               | to configure objects.         |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| namespace          | string    | Required  | n/a           | Kubernetes namespace to watch |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| kubeconfig         | string    | Optional  | ./config      | Path to the *kubeconfig* file |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| python-basedir     | string    | Optional  | /app/python   | Path to python utilities      |                   |
|                    |           |           |               | directory                     |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| running-in-cluster | boolean   | Optional  |  true         | Indicates whether or not a    | true, false       |
|                    |           |           |               | kubernetes cluster started    |                   |
|                    |           |           |               | ``k8s-bigip-ctlr``            |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| use-node-internal  | boolean   | Optional  | true          | filter Kubernetes InternalIP  | true, false       |
|                    |           |           |               | addresses for pool members    |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| verify-interval    | integer   | Optional  | 30            | In seconds, interval at which |                   |
|                    |           |           |               | to verify the BIG-IP          |                   |
|                    |           |           |               | configuration.                |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| node-poll-interval | integer   | Optional  | 30            | In seconds, interval at which |                   |
|                    |           |           |               | to poll the cluster for its   |                   |
|                    |           |           |               | node members.                 |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| log-level          | string    | Optional  | INFO          | Log level                     | INFO,             |
|                    |           |           |               |                               | DEBUG,            |
|                    |           |           |               |                               | CRITICAL,         |
|                    |           |           |               |                               | WARNING,          |
|                    |           |           |               |                               | ERROR             |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| pool-member-type   | string    | Optional  | nodeport      | Defines the                   | nodeport, cluster |
|                    |           |           |               | `Kubernetes Service Type`_    |                   |
|                    |           |           |               | applied to the pool member    |                   |
|                    |           |           |               | (NodePort or ClusterIP)       |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| openshift-sdn-name | string    | Optional  | n/a           | BigIP configured VxLAN name   |                   |
|                    |           |           |               | for access into the Openshift |                   |
|                    |           |           |               | SDN and Pod network           |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+



F5 Resource Properties
----------------------

F5 Resources are JSON blobs encoded within Kubernetes ConfigMaps. The ConfigMap must contain the following properties:

+---------------+---------------------------------------------------+-----------------------------------------------+
| Property      | Description                                       | Allowed Values                                |
+===============+===================================================+===============================================+
| f5type        | Defines the type of object                        | virtual-server                                |
|               | ``k8s-bigip-ctlr`` creates on the BIG-IP          |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+
| schema        | Verifies the ``data`` blob                        | f5schemadb://bigip-virtual-server_v0.1.2.json |
+---------------+---------------------------------------------------+-----------------------------------------------+
| data          | Defines the F5 resource                           |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+
| frontend      | Defines object(s) created on the BIG-IP           | See `frontend <#frontend>`_                   |
+---------------+---------------------------------------------------+-----------------------------------------------+
| backend       | Identifes the Kubernets Service acting as the     | See `backend <#backend>`_                     |
|               | server pool                                       |                                               |
+---------------+---------------------------------------------------+-----------------------------------------------+

Frontend
````````

virtualServer
~~~~~~~~~~~~~
+-------------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| Property          | Type      | Required  | Default   | Description                   | Allowed Values            |
+===================+===========+===========+===========+===============================+===========================+
| partition         | string    | Required  |           | Define the BIG-IP partition   |                           |
|                   |           |           |           | to manage                     |                           |
+-------------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| mode              | string    | Required  |           | Set the proxy mode            | http, tcp                 |
+-------------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| balance           | string    | Required  | round-    | Set the load balancing mode   | round-robin               |
|                   |           |           | robin     |                               |                           |
+-------------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| virtualAddress    | JSON      | Required  |           | Allocate a virtual address    |                           |
|                   | object    |           |           | from the BIG-IP               |                           |
+---+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
|   | bindAddr      | string    | Required  |           | Virtual IP address            |                           |
+---+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
|   | port          | integer   | Required  |           | Port number                   |                           |
+---+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| sslProfile        | JSON      | Optional  |           | BIG-IP SSL profile to use to  |                           |
|                   | object    |           |           | access virtual server.        |                           |
+---+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
|   | f5ProfileName | string    | Optional  |           | Name of the BIG-IP SSL        |                           |
|   |               |           |           |           | profile.                      |                           |
|   |               |           |           |           |                               |                           |
|   |               |           |           |           | Uses format 'partition_name/  |                           |
|   |               |           |           |           | cert_name'                    |                           |
|   |               |           |           |           |                               |                           |
|   |               |           |           |           | Example: 'Common/testcert'    |                           |
+---+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+

iApps
~~~~~

+---------------------+-----------+-----------+-----------+-------------------------------------------------------+---------------------------+
| Property            | Type      | Required  | Default   | Description                                           | Allowed Values            |
+=====================+===========+===========+===========+=======================================================+===========================+
| partition           | string    | Required  |           | Define the BIG-IP partition                           |                           |
|                     |           |           |           | to manage.                                            |                           |
+---------------------+-----------+-----------+-----------+-------------------------------------------------------+---------------------------+
| iapp                | string    | Required  |           | BIG-IP iApp template to use                           | Any iApp template already |
|                     |           |           |           | to create the application                             | configured on the BIG-IP. |
|                     |           |           |           | service.                                              |                           |
+---------------------+-----------+-----------+-----------+-------------------------------------------------------+---------------------------+
| iappPoolMemberTable | JSON      | Required  |           | Defines the name and layout of the pool-member table  |                           |
|                     | object    |           |           | in the iApp.                                          |                           |
|                     |           |           |           | See the iApp Pool Member Table section below.         |                           |
+---------------------+-----------+-----------+-----------+-------------------------------------------------------+---------------------------+
| iappTables          | JSON      | Optional  |           | Define iApp tables to apply to                        |                           |
|                     | object    |           |           | the Application Service                               |                           |
|                     | array     |           |           |                                                       |                           |
|                     |           |           |           | Example:                                              |                           |
|                     |           |           |           | ``"iappTables": {``                                   |                           |
|                     |           |           |           | ``"monitor__Monitors":``                              |                           |
|                     |           |           |           | ``{"columns": ["Index", "Name", "Type", "Options"],`` |                           |
|                     |           |           |           | ``"rows": [[0, "mon1", "tcp", "" ],``                 |                           |
|                     |           |           |           | ``[1, "mon2", "http", ""]]}}"``                       |                           |
+---------------------+-----------+-----------+-----------+-------------------------------------------------------+---------------------------+
| iappOptions         | key-value | Required  |           | Define the App configurations                         | See configuration         |
|                     | object    |           |           |                                                       | parameters above.         |
+---------------------+-----------+-----------+-----------+-------------------------------------------------------+---------------------------+
| iappVariables       | key-value | Required  |           | Define of iApp variables                              |                           |
|                     | object    |           |           | needed for service creation.                          |                           |
+---------------------+-----------+-----------+-----------+-------------------------------------------------------+---------------------------+

iApp Pool Member Table
``````````````````````

You can use the ``iappPoolMemberTable`` option to describe the layout of the pool-member table that the controller should configure.  It is a JSON object with these properties:

- ``name`` (required): A string that specifies the name of the table that contains the pool members.
- ``columns`` (required): An array that specifies the columns that the controller will configure in the pool-member table, in order.

Each entry in ``columns`` is an object that has a ``name`` property and either a ``kind`` or ``value`` property:

- ``name`` (required): A string that specifies the column name.
- ``kind``: A string that tells the controller what property from the node to substitute.  The controller supports ``"IPAddress"`` and ``"Port"``.
- ``value``: A string that specifies a value.  The controller will not perform any substitution, it uses the value as specified.

For instance, if you configure an application with two pods at 1.2.3.4:20123 and 1.2.3.5:20321, and you specify::

    "iappPoolMemberTable" = {
      "name": "pool__members",
      "columns": [
        {"name": "Port", "kind": "Port"},
        {"name": "IPAddress", "kind": "IPAddress"},
        {"name": "ConnectionLimit", "value": "0"}
      ]
    }

This would configure the following table on BIG-IP::

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

You will need to adjust this for the particular iApp template that you are using.  One way to discover the format is to configure an iApp manually from a template, and then check its configuration using ``tmsh list sys app service <appname>``.


Backend
```````

+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| Property      | Type      | Required  | Default   | Description                   | Allowed Values            |
+===============+===========+===========+===========+===============================+===========================+
| serviceName   | string    | Required  | none      | The `Kubernetes Service`_     |                           |
|               |           |           |           | representing the server pool. |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| servicePort   | integer   | Required  | none      | Kubernetes Service port       |                           |
|               |           |           |           | number                        |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| healthMonitors| JSON      | Optional  | none      | Array of TCP or HTTP Health   |                           |
|               | object    |           |           | Monitors.                     |                           |
|               | array     |           |           |                               |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+


Example Configuration Files
```````````````````````````
- `sample-k8s-bigip-ctlr.yaml <./_static/config_examples/sample-k8s-bigip-ctlr.yaml>`_
- `sample-k8s-bigip-ctlr-secrets.yaml <./_static/config_examples/sample-k8s-bigip-ctlr-secrets.yaml>`_
- `sample-bigip-credentials-secret.yaml <./_static/config_examples/sample-bigip-credentials-secret.yaml>`_
- `example-vs-resource.configmap.yaml <./_static/config_examples/example-vs-resource.configmap.yaml>`_
- `example-vs-resource.json <./_static/config_examples/example-vs-resource.json>`_
- `example-vs-resource-iapp.json <./_static/config_examples/example-vs-resource-iapp.json>`_
- `example-advanced-vs-resource-iapp.json <./_static/config_examples/example-advanced-vs-resource-iapp.json>`_



API Endpoints
-------------
- Coming soon!


.. [#objectpartition]  The F5 Kubernetes BIG-IP Controller creates and manages objects in the BIG-IP partition defined in the `F5 resource`_ ConfigMap.
.. [#nodeport]  The F5 Kubernetes BIG-IP Controller forwards traffic to the NodePort assigned to the service by Kubernetes; see the Kubernetes `Services <http://kubernetes.io/docs/user-guide/services/>`_ documentation for more information.
.. [#secrets]  You can store sensitive information as a `Kubernetes Secret <http://kubernetes.io/docs/user-guide/secrets/>`_. See the `user documentation <#>`_ for instructions.
.. [#dclogin]  Requires login to DevCentral.





.. _Kubernetes: https://kubernetes.io/
.. _Kubernetes Service: https://kubernetes.io/docs/user-guide/services/
.. _Kubernetes clusters: https://kubernetes.io/docs/admin/
.. _NodePorts: https://kubernetes.io/docs/user-guide/services/#type-nodeport
.. _iApps: https://devcentral.f5.com/iapps
.. _Kubernetes pods: https://kubernetes.io/docs/user-guide/pods/
.. _Kubernetes Ingress resources: https://kubernetes.io/docs/user-guide/ingress/
.. _iApp table: https://devcentral.f5.com/wiki/iApp.Working-with-Tables.ashx
.. _F5 resource: <add link to F5 Resource doc>
.. _Kubernetes Service Type: https://kubernetes.io/docs/user-guide/services/#publishing-services---service-types

