k8s-bigip-ctlr
==============

.. toctree::
    :hidden:
    :maxdepth: 2


F5-k8s-bigip-ctlr is a tool for managing F5 BIG-IP `Local Traffic Manager <https://f5.com/products/big-ip/local-traffic-manager-ltm>`_ (LTM) services from `Kubernetes`_. The f5-k8s-bigip-ctlr can be deployed in Kubernetes as described in the `documentation <#>`_.

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

The ``k8s-bigip-ctlr`` is a Docker container that can run in a `Kubernetes`_ Pod. A special type of Kubernetes ConfigMap resource, called an `F5 resource`_, passes encoded data to ``k8s-bigip-ctlr``, telling it:

1. what objects to configure on your BIG-IP, and
2. to which `Kubernetes Service`_ the BIG-IP objects belong.

The ``k8s-bigip-ctlr`` watches the Kubernetes API for the creation and modification of F5 resources.
When it discovers changes, the ``k8s-bigip-ctlr`` modifies the BIG-IP accordingly.

For example:

1. The controller detects creation of an F5 ``virtualServer`` resource.
2. The controller creates a new virtual server object on the BIG-IP; [#objectpartition]_
3. The controller creates pool members on the virtual server for each node in the Kubernetes cluster; [#nodeport]_
4. The controller monitors the F5 resources and linked Kubernetes resources for changes and dynamically reconfigures the BIG-IP as needed.

The BIG-IP then handles traffic for the Service on the specified virtual address and load-balances to all nodes in the cluster. Within the cluster, the allocated NodePort is load-balanced to all pods for the Service.

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
| verify-interval    | integer   | Optional  | 30            | In seconds, internal at which |                   |
|                    |           |           |               | to verify the BIG-IP          |                   |
|                    |           |           |               | configuration.                |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| log-level          | string    | Optional  | INFO          | Log level                     | INFO,             |
|                    |           |           |               |                               | DEBUG,            |
|                    |           |           |               |                               | CRITICAL,         |
|                    |           |           |               |                               | WARNING,          |
|                    |           |           |               |                               | ERROR             |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| pool-member-type   | string    | Optional  | nodeport      | Defines the `Kubernetes       | nodeport, cluster |
|                    |           |           |               | Service Type`_ applied to the |                   |
|                    |           |           |               | pool member (NodePort or      |                   |
|                    |           |           |               | ClusterIP)                    |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+
| openshift-sdn-name | string    | Optional  | n/a           | BigIP configured VxLAN name   |                   |
|                    |           |           |               | for access into the Openshift |                   |
|                    |           |           |               | SDN and Pod network           |                   |
+--------------------+-----------+-----------+---------------+-------------------------------+-------------------+

F5 Resource Properties
----------------------

Front-end
`````````

Virtual Server
~~~~~~~~~~~~~~
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| Property      | Type      | Required  | Default   | Description                   | Allowed Values            |
+===============+===========+===========+===========+===============================+===========================+
| partition     | string    | Required  |           | The BIG-IP partition in which |                           |
|               |           |           |           | to create virtual server      |                           |
|               |           |           |           | objects.                      |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| mode          | string    | Required  |           | Proxy mode                    | http, tcp                 |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| balance       | string    | Required  | round-    | Load-balancing mode           | round-robin               |
|               |           |           | robin     |                               |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| virtualAddress| JSON      | Required  |           | Virtual address on the BIG-IP |                           |
|               | object    |           |           |                               |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| bindAddr      | string    | Required  |           | Virtual IP address            |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| port          | integer   | Required  |           | Port number                   |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| sslProfile    | JSON      | Optional  |           | BIG-IP SSL profile to use to  |                           |
|               | object    |           |           | access virtual server.        |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| f5ProfileName | string    | Optional  |           | Name of the BIG-IP SSL        | Uses format               |
|               |           |           |           | profile.                      | 'partition_name/cert_name'|
|               |           |           |           |                               | (e.g., 'Common/testcert') |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+

iApps
~~~~~

+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| Property      | Type      | Required  | Default   | Description                   | Allowed Values            |
+===============+===========+===========+===========+===============================+===========================+
| partition     | string    | Required  |           | The BIG-IP partition in which |                           |
|               |           |           |           | to create virtual server      |                           |
|               |           |           |           | objects.                      |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| iapp          | string    | Required  |           | BIG-IP iApp template to use   | Any iApp template already |
|               |           |           |           | to create the application     | configured on the BIG-IP. |
|               |           |           |           | service.                      |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| iappTableName | string    | Required  |           | `iApp table`_ entry specifying|                           |
|               |           |           |           | pool members. [#dclogin]_     |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| iappOptions   | key-value | Required  |           | The configuration options you | See configuration         |
|               | object    |           |           | want to apply to the          | parameters above.         |
|               |           |           |           | application service.          |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| iappVariables | key-value | Required  |           | Definition of iApp variables  |                           |
|               | object    |           |           | needed to create the service. |                           |
+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+




Backend
```````

+---------------+-----------+-----------+-----------+-------------------------------+---------------------------+
| Property      | Type      | Required  | Default   | Description                   | Allowed Values            |
+===============+===========+===========+===========+===============================+===========================+
| serviceName   | string    | Required  | none      | The Kubernetes Service that   |                           |
|               |           |           |           | represents the server pool.   |                           |
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



API Endpoints
-------------
- Coming soon!

-----------------------------

.. [#objectpartition]  The ``k8s-bigip-ctlr`` creates and manages objects in the BIG-IP partition defined in the `F5 resource`_ ConfigMap.
.. [#nodeport]  The ``k8s-bigip-ctlr`` forwards traffic to the NodePort assigned to the service by Kubernetes; see the Kubernetes `Services <http://kubernetes.io/docs/user-guide/services/>`_ documentation for more information.
.. [#secrets]  Can be stored as a `Kubernetes Secret <http://kubernetes.io/docs/user-guide/secrets/>`_. See the `user documentation <#>`_ for instructions.
.. [#dclogin]  Requires login to DevCentral.





.. _Kubernetes: <http://kubernetes.io/>
.. _Kubernetes Service:
.. _Kubernetes clusters: http://kubernetes.io/docs/admin/
.. _NodePorts: http://kubernetes.io/docs/user-guide/services/#type-nodeport
.. _iApps: https://devcentral.f5.com/iapps
.. _Kubernetes pods: http://kubernetes.io/docs/user-guide/pods/
.. _Kubernetes Ingress resources: http://kubernetes.io/docs/user-guide/ingress/
.. _iApp table: https://devcentral.f5.com/wiki/iApp.Working-with-Tables.ashx
.. _F5 resource: <add link to F5 Resource doc>
.. _Kubernetes Service Type: https://kubernetes.io/docs/user-guide/services/#publishing-services---service-types
