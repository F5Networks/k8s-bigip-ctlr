.. _csi_k-home:

F5 |csi_k|
==========

Overview
--------

.. csik-overview-body-start

The F5® |csi| (CSI) makes L4-L7 services available to users deploying microservices-based applications in a containerized infrastructure. [#f1]_
The |csi_k| allows you to expose a `Kubernetes Service`_ outside the cluster as a virtual server on a BIG-IP® :term:`device` entirely through the `Kubernetes`_ API.

.. [#f1] See `Using Docker Container Technology with F5 Products and Services <https://f5.com/resources/white-papers/using-docker-container-technology-with-f5-products-and-services>`_

.. csik-overview-body-end

Architecture
------------

.. csik-architecture-body-start

The |csi_k| is a Docker container that can run in `Kubernetes`_.
Once installed, it watches for `Kubernetes Service`_ resources and F5 Virtual Server Resources, which are stored as Kubernetes `ConfigMap`_ resources.

When the |csi_k| discovers a Service and an associated F5 Virtual Server Resource, it creates a new virtual server for the service on the BIG-IP.
The |csi_k| also creates pool members for each node in the cluster.



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
- A partition configured on the BIG-IP that will only be used by |csi_k|.
- A running `Kubernetes`_ cluster.
- ``kubectl`` (the `Kubernetes`_ CLI) installed, and configured with admin access to the cluster.
- The official ``f5-k8s-controller`` image pulled from the `F5 Docker registry`_.

Caveats
-------

- You must create the partition you wish to manage from Kubernetes on the BIG-IP *before* configuring the CSI.

.. csik-prereqs-body-end

.. _csik-install-section:

Install the |csi_k|
-------------------

.. csik-install-body-start

To install the |csi_k|, create a `Kubernetes Deployment`_ for the ``f5-k8s-controller``. The deployment creates a `ReplicaSet <http://kubernetes.io/docs/user-guide/replicasets/>`_ which ensures there is always a `Pod <http://kubernetes.io/docs/user-guide/pods/>`_ running the ``f5-k8s-controller`` container.


#. Create a Kubernetes Secret to store the BIG-IP credentials:

   #. Create a file for each parameter. Use the parameter name for the file name, and the parameter value for the file contents:

      .. code-block:: bash

            echo <YOUR-BIGIP-IPADDRESS> > url
            echo <YOUR-BIGIP-USERNAME> > username
            echo <YOUR-BIGIP-PASSWORD> > password

   #. Create a secret named ``bigip-credentials`` in Kubernetes from the files:

      .. code-block:: bash

            kubectl create secret generic bigip-credentials --from-file=username --from-file=password --from-file=url

   #. Verify the secret was created correctly.
   
      ..note:: The values are base64 encoded, and will differ from the example shown here.

      .. code-block:: bash

          kubectl get secret bigip-credentials -o yaml

      .. literalinclude:: /static/f5-csi_k/sample-bigip-credentials.yaml

#. Create a Kubernetes Deployment to run ``f5-k8s-controller``:

   #. Create a new file to define the `Kubernetes Deployment`_.

      * Provide the ``f5-k8s-controller`` Docker image name in the ``containers`` section.
      * The BIG-IP credentials will be pulled from the ``bigip-credentials`` secret just created.
      * If needed, customize the args section with :ref:`Configuration Parameters <csik_configuration-parameters>`.


      .. literalinclude:: /static/f5-csi_k/sample-f5-k8s-controller-secrets.yaml
          :emphasize-lines: 20, 39-42


   #. Upload the Deployment configuration to Kubernetes.

      .. code-block:: bash

          kubectl create -f f5-k8s-controller.yaml

   #. Verify the creation of your Deployment.

      .. code-block:: bash

          kubectl get deployment f5-k8s-controller --namespace kube-system


.. csik-install-body-end

.. csik-config-start

.. _configuration-section:

Configure the |csi_k|
---------------------

If needed, configure the F5 |csi_k| by passing command line arguments to the f5-k8s-controller.

.. _csik_configuration-parameters:

Configuration Parameters
````````````````````````

.. include:: /includes/f5-csi_k/ref_csik-table-configuration-parameters.rst

.. csik-config-end

.. csik-usage-start


.. _csik-usage-section:

Usage
-----

The F5® |csi_k-long| uses special F5 Virtual Server resources in Kubernetes to describe how a `Kubernetes Service`_ should be exposed as a virtual server on the BIG-IP.
The F5 Virtual Server resource both directs the |csi_k| to apply configurations to the BIG-IP and ties those configurations to the Service.

.. important::

    * The Kubernetes Service's `ServiceType <http://kubernetes.io/docs/user-guide/services/#publishing-services---service-types>`_ must be "NodePort". This exposes the same port number on each node in the cluster for the service port. This allows the BIG-IP to connect to the service from outside the cluster.
    * An F5 Virtual Server resource defines a virtual server for one (1) port, for one (1) `Kubernetes Service`_.
      You must create an F5 Virtual Server resource for each Service port you wish to expose to the BIG-IP.

The |csi_k| watches for F5 resources and manages the BIG-IP according to the resource's definitions.
When it discovers changes, |csi_k| will configure the BIG-IP accordingly. For each F5 Virtual Server, the |csi_k| will:

    - create objects to represent the virtual server on the BIG-IP in the specified partition,
    - create pool members for each node in the Kubernetes cluster, using the NodePort Kubernetes assigned to the service port,
    - monitor the F5 resources and linked Kubernetes resources for changes, reconfiguring the BIG-IP accordingly.

The BIG-IP will then handle traffic on the specified virtual address, and load-balance to all nodes in the cluster.
Within the cluster, that NodePort will be load-balanced to all pods for the service.

.. warning::

    The |csi_k| manages objects on the BIG-IP in the partition specified in f5-k8s-controller configuration. We strongly recommend that you do not manage objects in this partition outside of Kubernetes.

.. _csi_k-encode-resources:

Encoding an F5 Resource in Kubernetes
`````````````````````````````````````

When configuring an F5 resource in Kubernetes, it must be encoded as a `ConfigMap`_. 

It's important to note that although Kubernetes calls these objects ConfigMaps, they're not *traditional* Kubernetes ConfigMaps because they aren't attached to any Pods.
Instead, consider them 'F5 resources', as they only pertain to the F5 |csi|.

The ConfigMap that encodes an F5 resource must have a label: ``f5type``, and 2 properties: ``schema``, and ``data``.

    * The f5type label tells f5-k8s-controller which F5 resource type the `ConfigMap`_ represents.
    * The schema property tells f5-k8s-controller how to verify the content in the data property.
    * The data property contains the F5 Resource that is being encoded.

.. _csi_k-config-vs:

Configure an F5 Virtual Server
``````````````````````````````

The F5 Virtual Server is an F5 resource. It is a JSON object that must include:

    - a frontend property describing the Virtual Server on the BIG-IP, such as the virtualAddress; and
    - a backend property that selects the Kubernetes Service that should act as the server pool.

Frontend Configuration
~~~~~~~~~~~~~~~~~~~~~~

The frontend configuration defines how the service should be exposed on the BIG-IP.
You can specify either the :ref:`Standard Configuration <csik_config-vs-frontend-vs>`, or to use an :ref:`iApp Configuration <csik_config-vs-frontend-iapp>`.

.. _csi_k-config-vs-frontend:

.. include:: /includes/f5-csi_k/ref_config-parameters-frontend-vs.rst

.. include:: /includes/f5-csi_k/ref_config-parameters-frontend-vs-sslProfile.rst

.. include:: /includes/f5-csi_k/ref_config-parameters-frontend-vs-virtualAddress.rst

.. include:: /includes/f5-csi_k/ref_config-parameters-frontend-iapp.rst


Backend Configuration
~~~~~~~~~~~~~~~~~~~~~

The backend configuration identifies the Kubernetes Service, which will make up the server pool.

.. _csi_k-config-vs-backend:

.. include:: /includes/f5-csi_k/ref_config-parameters-backend.rst

Example Configuration
~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: /static/f5-csi_k/example-vs-resource.json

Example Configuration with an iApp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: /static/f5-csi_k/example-vs-resource-iapp.json

Create a Virtual Server with the F5 |csi_k|
```````````````````````````````````````````

.. _csi_k-f5-vs-resource-create:

Create the Virtual Server resource in Kubernetes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When F5 Resources are loaded into Kubernetes, they need to be :ref:`encoded as Kubernetes ConfigMap resources <csi_k-encode-resources>`. 

The F5 Virtual Server resource uses the following properties:

    * f5type: virtual-server
    * schema: ``f5schemadb://bigip-virtual-server_v0.1.0.json``
    * data: A string containing the json object for :ref:`Virtual Server configuration <csi_k-config-vs>`.

For example, if you want to encode a Virtual Server resource like the following:

    .. literalinclude:: /static/f5-csi_k/example-vs-resource.json

it needs to be encoded as a ConfigMap. Encoded in a ConfigMap, the example Virtual Server becomes the following YAML:

    .. literalinclude:: /static/f5-csi_k/example-vs-resource.configmap.yaml


#. Put the ConfigMap encoded data in a new file (e.g., "example-vs-configmap.yaml").


#. Use the ``kubectl create`` command to create the F5 Virtual Server resource. [#f2]_

   .. code-block:: bash

       kubectl create -f example-vs-configmap.yaml


.. [#f2] http://kubernetes.io/docs/user-guide/kubectl/kubectl_create_configmap/



Delete the F5 Virtual Server resource 
`````````````````````````````````````

To remove the F5 Virtual Server for a `Kubernetes Service`_ and remove all related objects from the BIG-IP, **remove the ConfigMap** from the Kubernetes API server.

    .. code-block:: bash

        kubectl delete configmap example-vs

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
