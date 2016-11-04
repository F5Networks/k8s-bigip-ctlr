.. _csi_k-home:

F5 |csi_k|
==========

Overview
--------

.. csik-overview-body-start

The F5® |csi| (CSI) makes L4-L7 services available to users deploying miscroservices-based applications in a containerized infrastructure. [#f1]_ The |csi_k| lets you configure load balancing on a BIG-IP® :term:`device` entirely through the `Kubernetes`_ API.

.. [#f1] See `Using Docker Container Technology with F5 Products and Services <https://f5.com/resources/white-papers/using-docker-container-technology-with-f5-products-and-services>`_

.. csik-overview-body-end

Architecture
------------

.. csik-architecture-body-start

The |csi_k| is a Docker container that can run in `Kubernetes`_. Once installed, it watches for the creation/destruction of `Kubernetes Service`_ objects and the creation/destruction of F5 Virtual Server Resources stored as `ConfigMap`_ definitions.

When the |csi_k| discovers a Service that has the BIG-IP :ref:`configuration parameters <csik_configuration-parameters>` set, it creates a new virtual server for the service on the BIG-IP. The |csi_k| also creates pool members for each node in the cluster.



.. csik-architecture-body-end

Use Case
--------

The F5 |csi_k| makes it possible to provision BIG-IP Local Traffic Manager™ (LTM®) services for North-South traffic (i.e., traffic in and out of the data center) via the Kubernetes API. You can use the |csi_k| in conjunction with the F5 :ref:`Lightweight Proxy <lwp-home>`, which provides services for East-West traffic (i.e., traffic between services/apps in the data center).


Prerequisites
-------------

.. csik-prereqs-body-start

- Licensed, operational `BIG-IP`_ :term:`device`.
- Knowledge of BIG-IP `system configuration`_ and `local traffic management`_.
- Administrative access to the BIG-IP.
- A `Kubernetes`_- or `Kubernetes Service`_-specific partition configured on the BIG-IP.
- A running `Kubernetes`_ cluster.
- ``kubectl`` (the `Kubernetes`_ CLI) installed.
- The official ``f5-k8s-controller`` image pulled from the `F5 Docker registry`_.

Caveats
-------

- You must create the partition you wish to manage from Kubernetes on the BIG-IP *before* configuring the CSI.

.. csik-prereqs-body-end

.. _csik-install-section:

Install the |csi_k|
-------------------

.. csik-install-body-start

To install the |csi_k|, create a `Kubernetes Deployment`_. The deployment launches a `ReplicaSet <http://kubernetes.io/docs/user-guide/replicasets/>`_, then creates a `Pod <http://kubernetes.io/docs/user-guide/pods/>`_ that runs the ``f5-k8s-controller`` container.

.. tip::

    You can use JSON or YAML to define Kubernetes Deployments.

#. Create a new `Kubernetes Deployment`_ file.

#. Define the Deployment object.

    * Provide the URL for the ``f5-k8s-controller`` Docker image in the ``containers`` section.
    * Provide your BIG-IP username, password, and management IP address in the ``env`` section.
    * If desired, you can :ref:`store your BIG-IP credentials in a Kubernetes Secret <kubernetes-secret-bigip-login>` to keep them secure.


    .. literalinclude:: /static/f5-csi_k/sample-f5-k8s-controller.yaml
        :emphasize-lines: 6, 17, 19, 20-33


#. Upload the Deployment configuration to Kubernetes.

    .. code-block:: bash

        $ kubectl create -f f5-k8s-controller.json

#. Verify the creation of your Deployment.

    .. code-block:: bash

        $ kubectl get deployment f5-k8s-controller --namespace kube-system


.. csik-install-body-end

.. csik-config-start

.. _configuration-section:

Configuration
-------------

Use the configuration parameters, formatted as valid JSON or YAML, to configure the F5 |csi_k|.

.. _csik_configuration-parameters:

Configuration Parameters
````````````````````````

.. include:: /includes/f5-csi_k/ref_csik-table-configuration-parameters.rst

.. csik-config-end

.. csik-usage-start


.. _csik-usage-section:

Usage
-----

The F5® |csi_k-long| uses Kubernetes `ConfigMap`_ objects to create and configure a virtual server on the BIG-IP for a `Kubernetes Service`_.
The ConfigMap, which we treat as an F5 Virtual Server Resource, both directs the |csi_k| to apply configurations to the BIG-IP and ties those configurations to the Service.

It's important to note that although we call these objects ConfigMaps, they're not *traditional* Kubernetes ConfigMaps because they aren't attached to any Pods. Instead, consider them 'F5 resources', as they only pertain to the F5 |csi|. These resources may be represented as API extensions in future releases.

.. important::

    * The Kubernetes Service's `ServiceType <http://kubernetes.io/docs/user-guide/services/#publishing-services---service-types>`_ must be "NodePort". This exposes the same port number on each node in the cluster to the Service; this port will be used to communicate with the BIG-IP.
    * A `ConfigMap`_ defines a virtual server for one (1) port, for one (1) `Kubernetes Service`_.
    * You must create an F5 `ConfigMap`_ resource for each Service port you wish to expose to the BIG-IP.

The |csi_k| watches for F5 resources and manages the BIG-IP according to the the resource's definitions.
There are two ways to define virtual server configurations:

    * include the configurations :ref:`in the ConfigMap as F5-formatted string data <csi_k-f5-formatted-data-configmap>`, or
    * include the configurations in a separate JSON or YAML file and :ref:`reference the config file in the ConfigMap <csi_k-call-json-file-configmap>`.

The F5 virtual server ConfigMap resource must include:

    - the proper backend field selectors to identify the Service you want to load balance (name and port), and
    - the :ref:`configurations <csik_configuration-parameters>` you want the |csi| to apply to the BIG-IP.

When you add the F5 ConfigMap resource to Kubernetes, the |csi_k| does the following:

    - detects the port number allocated to the Service;
    - creates the virtual server on the BIG-IP in the specified partition,
    - assigns the virtual server to the port allocated to the Service by Kubernetes,
    - creates pool members for each node in the Kubernetes cluster.

The BIG-IP will then load balance traffic for all nodes in the cluster.

.. warning::

    The |csi_k| creates objects on the BIG-IP in the partition specified in the ConfigMap. We strongly recommend that you do not manage objects in this partition outside of Kubernetes.


Create a Virtual Server with the F5 |csi_k|
```````````````````````````````````````````

.. _csi_k-f5-formatted-data-configmap:

Use F5-formatted data in a ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All BIG-IP configurations included in the F5 `ConfigMap`_ resource must use the appropriate string formatting (f5-formatting). We provide a Json-Schema to describe the required format and enable programmatic validation of configured data, which should be called in the F5 ConfigMap resource as ``f5schemadb://bigip-virtual-server_v0.1.0.json``.


#. Create a new file for your F5 ConfigMap resource (e.g., "f5configmap").

#. Add the label ``"f5type": "virtual-server"`` to the ``metadata`` section.

     This label identifies the ConfigMap object as an F5 Virtual Server Resource. The CSI uses this label to identify ConfigMaps it should react to.

    .. code-block:: javascript
        :linenos:
        :lineno-start: 1
        :emphasize-lines: 5, 7-8

        {
          "kind": "ConfigMap",
          "apiVersion": "v1",
          "metadata": {
            "name": "demo-service",
            "namespace": "default",
            "labels": {
              "f5type": "virtual-server"
            }
          },

#. Add the BIG-IP configurations to the ``data`` section.

    * Call the F5 schema as ``"schema": "f5schemadb://bigip-virtual-server_v0.1.0.json"``.
    * Use proper F5-formatting. The data field must be a single string that adheres to the Json-Schema format.
    * Include the `Kubernetes Service`_ name and port in the ``backend`` section.
    * Define the BIG-IP configurations in the ``frontend`` section.

    .. code-block:: javascript
        :linenos:
        :lineno-start: 11

        "data": {
          "schema": "f5schemadb://bigip-virtual-server_v0.1.0.json",
          "data": "{\n  \"virtualServer\": {\n    \"backend\": {\n      \"serviceName\": \"demo-service\",\n      \"servicePort\": 10101\n    },\n    \"frontend\": {\n      \"partition\": \"kube-demo-service\",\n      \"mode\": \"tcp\",\n      \"balance\": \"round-robin\",\n      \"virtualAddress\": {\n        \"bindAddr\": \"172.16.2.3\",\n        \"port\": 5050\n      }\n    }\n  }\n}\n"
        }

#. Use the ``kubectl create`` command to create the F5 ConfigMap Resource. [#f2]_

   .. code-block:: bash

       kubectl create -f f5configmap



.. [#f2] http://kubernetes.io/docs/user-guide/kubectl/kubectl_create_configmap/


.. _csi_k-call-json-file-configmap:

Call a JSON file from a ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Create a valid JSON or YAML file.

    * Identify the Service in the ``backend`` section:

    .. code-block:: javascript
        :linenos:
        :lineno-start: 1

        {
          "virtualServer": {
            "backend": {
              "serviceName": "demo-service",
              "servicePort": 10101
            },
          }


    * Provide the BIG-IP configurations in the ``frontend`` section:

    .. code-block:: javascript
        :linenos:
        :lineno-start: 8

        "frontend": {
                  "partition": "velcro",
                  "mode": "tcp",
                  "balance": "round-robin",
                  "virtualAddress": {
                    "bindAddr": "172.16.2.3",
                    "port": 5050
                  }
                }
              }

#. Create a file schema and add "f5schemadb://bigip-virtual-server_v0.1.0.json".

   .. code-block:: bash

       echo "f5schemadb://bigip-virtual-server_v0.1.0.json" > schema

#. Create the ConfigMap.

    Call the 'data' JSON or YAML file and the 'schema' file via the ``kubectl create configmap <name> --from-file`` command.

    .. code-block:: bash

        $ kubectl create configmap demo-service --from-file data --from-file schema


Disable load balancing for a Kubernetes Service
```````````````````````````````````````````````

To disable load balancing for a `Kubernetes Service`_ and remove all related objects from the BIG-IP, **remove the ConfigMap** from the Kubernetes API server.

    .. code-block:: bash

        kubectl delete configmap demo-service

.. tip::

    * If you temporarily take down a `Kubernetes Service`_, leave the F5 ConfigMap resource in place. This ensures connectivity to the BIG-IP remains in place when the Service comes back up.

    * If you take down a Service and later deploy a new Service **with the same name**, the |csi_k| will apply the F5 ConfigMap resource to the new Service.

.. csik-usage-end

Further Reading
---------------

.. seealso::

    * `kubectl overview <http://kubernetes.io/docs/user-guide/kubectl-overview/>`_
    * `Kubernetes - What is a Deployment <http://kubernetes.io/docs/user-guide/deployments/#what-is-a-deployment>`_
    * `Using Kubernetes Deployment objects <http://kubernetes.io/docs/user-guide/kubectl-overview/>`_

.. toctree::
    :hidden:

    self
