F5 |csi_k|
==========

Overview
--------

The F5® |csi| (CSI) provides an integration for the `Kubernetes <http://kubernetes.io/>`_ orchestration environment that makes L4-L7 services available to users deploying miscroservices-based applications in a containerized infrastructure. [#]_

The CSI makes it possible to manage BIG-IP® with Kubernetes, providing networking services for North-South traffic. It can be used in conjunction with the :ref:`F5 FlowPoint Proxy`, which provides services for East-West traffic.

The CSI watches for Services being created and destroyed in Kubernetes. When a Service is created and associated with an F5-formatted ConfigMap_, the |csi| creates a new virtual server for that Service on the BIG-IP, scaling the pool members to each node in the cluster.

Use Case
--------



Prerequisites
-------------
- A configured and accessible kubernetes cluster.
- curl and/or kubectl installed.


Caveats
-------
-
-
-


Configuration
-------------

The F5® |csi| (CSI) can be configured as a kubernetes Deployment object. The
minimum required information will be the BIG-IP® credentials and configuration
information (the BIG-IP® location as a valid URI or IP address, the BIG-IP®
login username, the BIG-IP® login password, and finally a valid parition name
where configuration objects will be stored [the default is 'velcro']) and the
official F5 docker registry.

Example
~~~~~~~

The F5® |csi| (CSI) can be configured through the kubernetes UI or via command
line tools. The remaining steps use the CLI as an example method.

- Create a valid kubernetes Deployment object. Save JSON or YAML in a file. It is recommended the F5® |csi| (CSI) be created in the 'kube-system' namespace.

.. code-block:: javascript

    {
      "apiVersion": "extensions/v1beta1",
      "kind": "Deployment",
      "metadata": {
        "name": "f5-k8s-controller",
        "namespace": "kube-system"
      },
      "spec": {
        "replicas": 1,
        "template": {
          "metadata": {
            "name": "f5-k8s-controller",
            "labels": {
              "app": "f5-k8s-controller"
            }
          },
          "spec": {
            "containers": [
              {
                "name": "f5-k8s-controller",
                "image": ${F5-DOCKER-REGISTRY}/${F5-CTRL-CONTAINER}:${F5-TAG},
                "imagePullPolicy": "Always",
                "command": [ "/app/bin/f5-k8s-controller" ],
                  "args": [
                    "--bigip-url", "${BIGIPAdminPrivateIP}",
                    "--bigip-username", "admin",
                    "--bigip-password", "${BIGIPAdminPassword}"
                  ]
              }
            ]
          }
        }
      }
    }

- Use kubectl to upload configuration to the kubernetes API or alternately use curl.

.. code-block:: bash

    $ kubectl create -f f5-ctrl.json

.. code-block:: bash

    $ curl -X POST -H "Content-Type: application/json" --data @f5-ctrl.json http://[KUBE-API-SERVER]/apis/extensions/v1beta1/namespaces/kube-system/deployments/f5-k8s-controller

- Verify proper creation via kubectl or curl

.. code-block:: bash

    $ kubectl get deployment f5-k8s-controller --namespace kube-system

.. code-block:: bash

    $ curl http://[KUBE-API-SERVER]/apis/extensions/v1beta1/namespaces/kube-system/deployments/f5-k8s-controller

.. comment:: use the following template to create a table using the list-table format

.. list-table:: Configuration Parameters
    :header-rows: 1

    * - Name
      - Description
      - Default Setting
    * - ``--bigip-partition``
      - partition for configuring the BIG-IP objects
      - velcro
    * - ``--bigip-password``
      - password for the BIG-IP
      - N/A
    * - ``--bigip-url``
      - URL for the BIG-IP
      - N/A
    * - ``--bigip-username``
      - username for the BIG-IP
      - N/A
    * - ``--kubeconfig``
      - path to the *kubeconfig* file
      - N/A
    * - ``--namespace``
      - kubernetes namespace to watch
      - default
    * - ``--python-basedir``
      - directory location of python utilities
      - /app/python
    * - ``--running-in-cluster``
      - flag indicating if the controller was started by k8s
      - true
    * - ``--use-node-internal``
      - flag to filter kubernetes InternalIP addresses for pool members
      - true


Use Kubernetes Secrets to Import BIG-IP parameters
--------------------------------------------------

The BIG-IP parameters can be stored in a Kubernetes secret. The :file:`scripts/sample-bigip-credentials.yaml` file has an example configuration for this purpose. When used in combination with the :file:`scripts/sample-f5-k8s-controller.yaml` configuration file, the command line options to the controller for the BIG-IP are auto-populated from the secret.

Example
~~~~~~~

.. todo:: provide example

.. todo:: provide instructions

Configuring BIG-IP Load Balancing
---------------------------------

The BIG-IP load balancing for your application can be configured entirely
through the kubernetes API. This example assumes that that all Pods, Replication
Controllers, and/or Deployments have been setup and are working correctly. The
F5® |csi| (CSI) and BIG-IP are configured solely through Services and
specifically formatted ConfigMap objects.

F5 formatted ConfigMap objects provide application policy and metadata specific to BIG-IP
virtual server configuration. This data is associated to a kubernetes Service
(the object defining frontend characterics of the application) via field
selectors stored in the ConfigMap.

The order of operations in this example does not matter. The F5® |csi| (CSI)
will properly configure BIG-IP load balancing only when both objects exist and
not before. To remove load balancing from an application only the ConfigMap
object needs removal; Services can be left alone if that is the desired
behavior, and vice versa if a Service must be temporarily taken down.

For instance, if BIG-IP load balancing is needed for a Service it can have been
created at any time. One criterion that must be fulfilled is the Service's
"spec.type" must be "NodePort". The following example JSON describes a valid
frontable Service:

.. code-block:: javascript

  {
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {
      "name": "demo-service",
      "labels": {
        "app": "demo"
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

To enable load balancing this Service must be tied to an F5 formatted ConfigMap
defining BIG-IP essential configuration data. ConfigMaps store both keys and
values as strings, and an F5 formatted ConfigMap uses complex structured data to
convey information to the BIG-IP. Since it can be difficult to represent a valid F5
formatted ConfigMap for demonstration F5 provides a Json-Schema to describe the
format and enable programmatic validation of configured data. For example, a
valid ConfigMap configuring L4 round robin load balancing to the virtual address
172.16.2.3:5050 would be represented with this JSON:

.. code-block:: javascript

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
      "data": "{\n  \"virtualServer\": {\n    \"backend\": {\n      \"serviceName\": \"demo-service\",\n      \"servicePort\": 10101\n    },\n    \"frontend\": {\n      \"partition\": \"velcro\",\n      \"mode\": \"tcp\",\n      \"balance\": \"round-robin\",\n      \"virtualAddress\": {\n        \"bindAddr\": \"172.16.2.3\",\n        \"port\": 5050\n      }\n    }\n  }\n}\n"
    }
  }

Note: ConfigMaps must be labelled ("f5type": "virtual-server").
ConfigMap keys can be created from files making this structure easier to work
with, a file named 'data' containing the required structured data can be
uploaded to the API with this command:

.. code-block:: bash

  $ kubectl create configmap demo-service --from-file data

Using this JSON:

.. code-block:: javascript

  {
    "virtualServer": {
      "backend": {
        "serviceName": "demo-service",
        "servicePort": 10101
      },
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
  }

This ConfigMap describes two things. The frontend section describes changes and
configuration on the BIG-IP; virtual address, load balancing algorithm, etc. The
backend section supplies the field selectors for the kubernetes Service. The
Service named 'demo-service' with the port 10101 will be selected for load
balancing; because the Service is of type NodePort it will have a port exposed
on each kubernetes node for communication. The BIG-IP will be configured to load
balance using this port across all nodes in the cluster.

F5 formatted ConfigMaps define a virtual server for one Service's port. Services
that expose multiple ports for communication will require additional ConfigMaps
for each additional port.

To disable load balancing and deconfigure the BIG-IP the ConfigMap can be
removed from the kubernetes API server.

Further Reading
---------------
.. comment:: provide links to relevant documentation (BIG-IP, other velcro projects, other docs in this project) here

.. seealso::

    * x
    * y
    * z

.. [#] See `Using Docker Container Technology with F5 Products and Services <https://f5.com/resources/white-papers/using-docker-container-technology-with-f5-products-and-services>`_

.. _ConfigMap: http://kubernetes.io/docs/user-guide/configmap/
