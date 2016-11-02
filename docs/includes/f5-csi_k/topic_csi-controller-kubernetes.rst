.. _csi_k-home:

F5 |csi_k|
==========

Overview
--------

The F5® |csi| (CSC) makes L4-L7 services available to users deploying miscroservices-based applications in a containerized infrastructure. [#]_ The |csi_k-long| allows you to configure load balancing on a BIG-IP® :term:`device` entirely through the `Kubernetes`_ API.

Architecture
````````````

The |csi_k| is a Docker container that can run in `Kubernetes`_. Once installed, it watches for the creation/destruction of `Kubernetes Service`_ objects and the creation/destruction of F5 Virtual Server Resources stored as `ConfigMap`_ definitions. When it finds a properly-configured Service that is identified for load balancing by a F5 Virtual Server Resource, the CSC creates a new virtual server, with pool members for each node in the cluster, for that service on the BIG-IP.

.. [#] See `Using Docker Container Technology with F5 Products and Services <https://f5.com/resources/white-papers/using-docker-container-technology-with-f5-products-and-services>`_

Use Case
--------

The F5 |csi_k| makes it possible to provision BIG-IP Local Traffic Manager™ (LTM®) services for North-South traffic (i.e., traffic in and out of the data center) via the Kubernetes API. It can be used in conjunction with the F5 :ref:`Lightweight Proxy <lwp-home>`, which provides services for East-West traffic (i.e., traffic between services/apps in the data center).

.. todo:: add diagram

Prerequisites
-------------

In order to use the |csi_k-long|, you will need the following:

- Licensed, operational BIG-IP :term:`device`.
- Knowledge of BIG-IP `system configuration`_ and `local traffic management`_.
- Administrative access to the BIG-IP.
- A partition (other than Common) configured on the BIG-IP.
- A running `Kubernetes`_ cluster.
- ``kubectl`` (the `Kubernetes`_ CLI) installed.
- The official ``f5-k8s-controller`` image pulled from the `F5 Docker registry`_.

Caveats
-------

- You must create the partition you wish to manage from Kubernetes on the BIG-IP *before* configuring the CSI.
- The F5 |csi_k| can only provision LTM services for a `Kubernetes Service`_ if the "spec.type" is set to "NodePort".

Install the |csi_k|
-------------------

Install |csi_k| using a Kubernetes Deployment
`````````````````````````````````````````````

Create a `Kubernetes Deployment`_ to launch a new ReplicaSet and Pod running the ``f5-k8s-controller`` container.

.. tip::

    Kubernetes Deployments can be defined using JSON or YAML.

#. Create a new `Kubernetes Deployment`_ file.

#. Define the Deployment object.

    * Provide the URL for the ``f5-k8s-controller`` Docker image in the ``containers`` section.
    * Provide your BIG-IP username, password, and management IP address in the ``env`` section.
    * You can :ref:`store your BIG-IP credentials in a Kubernetes Secret <kubernetes-secret-bigip-login>` to keep them secure.


    .. literalinclude:: /static/f5-csi_k/sample-f5-k8s-controller.yaml
        :emphasize-lines: 6, 17, 19, 20-33


#. Upload the Deployment configuration to Kubernetes.

    Using ``kubectl``:

    .. code-block:: bash

        $ kubectl create -f f5-ctrl.json

#. Verify that your Deployment was created.

    Using ``kubectl``:

    .. code-block:: bash

        $ kubectl get deployment f5-k8s-controller --namespace kube-system

.. _configuration-section:

Configuration
-------------

The F5 |csi_k| can be configured, using the parameters below, with valid JSON or YAML.

.. _csik_configuration-parameters:

Configuration Parameters
````````````````````````

.. include:: /includes/f5-csi_k/ref_csik-table-configuration-parameters.rst

Usage
-----

The F5® |csi_k-long| uses `ConfigMap`_ objects to create and configure a virtual server on the BIG-IP for a `Kubernetes Service`_. The ConfigMap is used as an F5 Virtual Server Resource and both directs the |csi_k| to apply configurations to the BIG-IP and ties those configurations to the Service. Although `Kubernetes`_ views these objects as ConfigMaps, they are not intended to be used as such; i.e. they won't be attached to any Pods. The f5-k8s-controller watches for these special resources and manages BIG-IP accordingly. These ConfigMaps should be considered as F5 typed resources and may be represented as API extensions in future releases.

.. warning::

    The |csi_k| creates objects on the BIG-IP in the partition specified in the ConfigMap. We strongly recommend that you only manage objects in this partition from Kubernetes.

You can define the virtual server that will be created on the BIG-IP for a Service by :ref:`including the configurations in the ConfigMap <csi_k-f5-formatted-data-configmap>` as F5-formatted string data, or by :ref:`calling a JSON or YAML file from the ConfigMap <csi_k-call-json-file-configmap>`.

.. _f5-formatted-data:

F5-Formatted Data
`````````````````

If you choose to include your BIG-IP configurations in the `ConfigMap`_, you must use the appropriate string formatting (f5-formatting).

F5 provides a Json-Schema -- called in the ConfigMap as ``f5schemadb://bigip-virtual-server_v0.1.0.json`` -- to describe the required format and enable programmatic validation of configured data.

.. important::

    * The |csi_k| can only manage a Service if its "spec.type" is set to "NodePort".

    .. rubric:: Example "NodePort" Service

    .. code-block:: javascript
        :linenos:
        :emphasize-lines: 20

        {
          "apiVersion": "v1",
          "kind": "Service",
          "metadata": {
            "name": "some-service",
            "labels": {
              "app": "demo_service_app"
            }
          },
          "spec": {
            "ports": [
              {
                "name": "demo-svc",
                "port": 10101
              }
            ],
            "selector": {
              "app": "demo"
            },
            "type": "NodePort"
          }
        }

Create a Virtual Server with the F5 |csi_k|
```````````````````````````````````````````

All BIG-IP configurations are applied using Kubernetes ConfigMaps. You can either include the configurations in the `ConfigMap`_ directly, using the :ref:`F5-formatted data <f5-formatted-data>` section, or call a JSON file which contains the data to be inserted as a key/value pair in your ConfigMap.

.. important::

    * A `ConfigMap`_ can define a virtual server for one (1) port, for one (1) `Kubernetes Service`_. Each Service port you wish to expose must have its own `ConfigMap`_.
    * Use the ``serviceName`` configuration parameter to identify the `Kubernetes Service`_ for which you want to create a virtual server.

.. _csi_k-f5-formatted-data-configmap:

Use F5-formatted data in a ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Create a new file for your ConfigMap (e.g., "myconfigmap").

#. Define the ``"f5type": "virtual-server"`` in the ``labels`` section.

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

    * Call the F5 schema as shown below.
    * Use proper F5-formatting. The format is defined as Json-Schema, the data field must adhere to this formatting structure but included as a single string.
    * Add the schema field with a value of "f5schemadb://bigip-virtual-server_v0.1.0.json".
    * Define the `Kubernetes Service`_ name and port in the ``backend`` section.
    * Define the BIG-IP configurations in the ``frontend`` section.

    .. code-block:: javascript
        :linenos:
        :lineno-start: 11

        "data": {
          "schema": "f5schemadb://bigip-virtual-server_v0.1.0.json",
          "data": "{\n  \"virtualServer\": {\n    \"backend\": {\n      \"serviceName\": \"demo-service\",\n      \"servicePort\": 10101\n    },\n    \"frontend\": {\n      \"partition\": \"kube-demo-service\",\n      \"mode\": \"tcp\",\n      \"balance\": \"round-robin\",\n      \"virtualAddress\": {\n        \"bindAddr\": \"172.16.2.3\",\n        \"port\": 5050\n      }\n    }\n  }\n}\n"
        }

#. Use the ``kubectl create`` command to create the `ConfigMap`_. [#]_

   .. code-block:: bash

       kubectl create -f myconfigmap




.. [#] http://kubernetes.io/docs/user-guide/kubectl/kubectl_create_configmap/

.. _csi_k-call-json-file-configmap:

Call a JSON file from a ConfigMap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Create a valid JSON file data that defines the `Kubernetes Service`_ to manage and the configurations to apply to the BIG-IP.

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

#. Create a file schema and add "f5schemadb://bigip-virtual-server_v0.1.0.json"

   .. code-block:: bash

       echo "f5schemadb://bigip-virtual-server_v0.1.0.json" > schema

#. Use the ``kubectl create configmap`` command to create the ConfigMap using the 'data' JSON file and schema file.

    .. code-block:: bash

        $ kubectl create configmap demo-service --from-file data --from-file schema



Configuration Examples
~~~~~~~~~~~~~~~~~~~~~~

The examples below both apply the same configurations to the BIG-IP. First, we create a virtual server for our `Kubernetes Service`_ ("demo-service"); the Service is uniquely defined by its name and port, in this example "demo-service" and 10101 respectively . Because the Service ``type`` is ``NodePort``, a port in the configured NodePort range will be exposed for communication on each Kubernetes node. This does not need to be known before hand, the ``f5-k8s-controller`` will automatically configure the BIG-IP with this information.

Once a `Kubernetes Service`_ is created and an F5 Virtual Server Resource (as a ConfigMap) is created with the proper backend field selector (Service's name and port). Then, the ``f5-k8s-controller`` automatically creates a virtual server on the BIG-IP in the "kube-demo-service" partition. It routes TCP traffic to the virtual IP address 172.16.2.3 at port 5050, using the "round-robin" load balancing algorithm.

The BIG-IP will now load balance traffic for all nodes in the Kubernetes cluster.


.. rubric:: F5-formatted data:

.. code-block:: javascript
    :linenos:

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
      "data": {
        "schema": "f5schemadb://bigip-virtual-server_v0.1.0.json",
        "data": "{\n  \"virtualServer\": {\n    \"backend\": {\n      \"serviceName\": \"demo-service\",\n      \"servicePort\": 10101\n    },\n    \"frontend\": {\n      \"partition\": \"kube-demo-service\",\n      \"mode\": \"tcp\",\n      \"balance\": \"round-robin\",\n      \"virtualAddress\": {\n        \"bindAddr\": \"172.16.2.3\",\n        \"port\": 5050\n      }\n    }\n  }\n}\n"
      }
    }

.. rubric:: JSON blob:

.. code-block:: javascript
    :linenos:

    {
      "virtualServer": {
        "backend": {
          "serviceName": "demo-service",
          "servicePort": 10101
        },
        "frontend": {
          "partition": "kube-demo-service",
          "mode": "tcp",
          "balance": "round-robin",
          "virtualAddress": {
            "bindAddr": "172.16.2.3",
            "port": 5050
          }
        }
      }
    }


Disable Load Balancing
``````````````````````

#. To remove load balancing from an application, remove the `ConfigMap`_ object.

    .. tip:: If you wish to temporarily take down a `Kubernetes Service`_, remove the Service object and leave the ConfigMap in place.

#. To disable load balancing and remove all related objects from the BIG-IP, **remove the ConfigMap** from the Kubernetes API server.



Further Reading
---------------

.. seealso::

    * `kubectl overview <http://kubernetes.io/docs/user-guide/kubectl-overview/>`_
    * `Kubernetes - What is a Deployment <http://kubernetes.io/docs/user-guide/deployments/#what-is-a-deployment>`_
    * `Using Kubernets Deployment objects <http://kubernetes.io/docs/user-guide/kubectl-overview/>`_

.. toctree::
    :hidden:

    self
