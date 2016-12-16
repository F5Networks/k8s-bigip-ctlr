.. _csi_k-home:

F5 |csi_k|
==========

Overview
--------

.. csik-overview-body-start

The F5® |csi| (CSI) makes L4-L7 services available to users deploying microservices-based applications in a containerized infrastructure. [#]_
The |csi_k| allows you to expose a `Kubernetes Service`_ outside the cluster as a virtual server on a BIG-IP® :term:`device` entirely through the `Kubernetes`_ API.

.. [#] See `Using Docker Container Technology with F5 Products and Services <https://f5.com/resources/white-papers/using-docker-container-technology-with-f5-products-and-services>`_

.. csik-overview-body-end

Architecture
------------

.. csik-architecture-body-start

The |csi_k-long| comprises the ``f5-k8s-controller`` and user-defined "F5 resources".
The ``f5-k8s-controller`` is a Docker container that can run in a `Kubernetes`_ Pod.
The "F5 resources" are Kubernetes `ConfigMap`_ resources that pass encoded data to the ``f5-k8s-controller``. These resources tell the ``f5-k8s-controller`` a) what objects to configure on your BIG-IP and b) what `Kubernetes Service`_ the BIG-IP objects belong to (the :ref:`frontend <csik-config-vs-frontend>` and :ref:`backend <csik-config-vs-backend>` properties in the ConfigMap, respectively).

The ``f5-k8s-controller`` watches for the creation and modification of F5 resources in Kubernetes.
When it discovers changes, it modifies the BIG-IP accordingly.
For example, for an F5 ``virtualServer`` resource, the |csi_k| does the following:

    - creates objects to represent the virtual server on the BIG-IP in the specified partition;
    - creates pool members for each node in the Kubernetes cluster, using the NodePort  assigned to the service port by Kubernetes; [#]_
    - monitors the F5 resources and linked Kubernetes resources for changes and reconfigures the BIG-IP accordingly.

The BIG-IP then handles traffic for the Service on the specified virtual address and load-balances to all nodes in the cluster. Within the cluster, the allocated NodePort is load-balanced to all pods for the Service.

.. [#] See the Kubernetes `ServiceType <http://kubernetes.io/docs/user-guide/services/#publishing-services---service-types>`_ documentation for more information about node ports.

.. csik-architecture-body-end

Use Case
--------

The F5 |csi_k| allows you to manage North-South traffic (i.e., traffic in and out of the data center) with a BIG-IP using the Kubernetes API. You can use the |csi_k| in conjunction with the F5 :ref:`Lightweight Proxy <lwp-home>`, which provides services for East-West traffic (i.e., traffic between services/apps in the data center).

Prerequisites
-------------

.. csik-prereqs-body-start

- Licensed, operational `BIG-IP`_ :term:`device`.
- Knowledge of BIG-IP `system configuration`_ and `local traffic management`_.
- Administrative access to the BIG-IP. [#]_
- A BIG-IP :term:`partition(s)` that will only be used by |csi_k|.
- A running `Kubernetes`_ cluster.
- ``kubectl`` (the `Kubernetes`_ CLI) installed and configured with admin access to the cluster.
- The official ``f5-k8s-controller`` image; contact your F5 Sales rep or go to `F5 DevCentral <https://devcentral.f5.com/welcome-to-the-f5-beta-program>`_ to request access to the beta program.

.. [#] Admin access to the BIG-IP is required to create the :term:`partition(s)` the CSI will manage; the BIG-IP user whose credentials you supply to the ``f5-k8s-controller`` only needs permission to configure objects in the partition.

Caveats
```````

- The partition(s) on the BIG-IP that you wish to manage from Kubernetes must exist *before* you install / configure the CSI.
- *We strongly recommend that you do not manage objects in this partition outside of Kubernetes.*

.. csik-prereqs-body-end

.. _csik-install-section:

Install the |csi_k|
-------------------

.. csik-install-body-start

To install the |csi_k|, create a `Kubernetes Deployment`_ for the ``f5-k8s-controller``. The deployment creates a `ReplicaSet <http://kubernetes.io/docs/user-guide/replicasets/>`_ which ensures there is always a `Pod <http://kubernetes.io/docs/user-guide/pods/>`_ running the ``f5-k8s-controller`` container.


#. Create a Kubernetes Secret to securely store your BIG-IP credentials:

    .. code-block:: bash

        $ kubectl create secret generic bigip-credentials //
         --from-literal=username=<yourusername> //
         --from-literal=password=<yourpassword> --from-literal=url=<bigip-url>

#. Verify the secret was created correctly.

    .. note:: The values are base64 encoded and will differ from the example shown here.

    .. code-block:: bash

      $ kubectl get secret bigip-credentials -o yaml


    .. literalinclude:: /static/f5-csi_k/sample-bigip-credentials.yaml
          :caption: Sample bigip-credentials

#. Create a new `Kubernetes Deployment`_ to run ``f5-k8s-controller``:

    * Provide the ``f5-k8s-controller`` Docker image name in the ``containers`` section.
    * The BIG-IP credentials will be pulled from the ``bigip-credentials`` secret just created.
    * If needed, customize the args section with the :ref:`Configuration Parameters <csik_configuration-parameters>`.

    \

    .. literalinclude:: /static/f5-csi_k/sample-f5-k8s-controller-secrets.yaml
      :caption: Sample f5-k8s-controller Deployment
      :emphasize-lines: 20, 39-42


#. Upload the Deployment configuration to Kubernetes.

    .. code-block:: bash

      $ kubectl create -f f5-k8s-controller.yaml

#. Verify the creation of your Deployment.

    .. code-block:: bash

        $ kubectl get deployment f5-k8s-controller --namespace kube-system


.. csik-install-body-end

.. csik-config-start

.. _configuration-section:

Configure the |csi_k|
---------------------

.. _csik_configuration-parameters:

The following can be passed to the ``f5-k8s-controller`` as command line arguments.

.. include:: /includes/f5-csi_k/ref_csik-table-configuration-parameters.rst


.. csik-config-end

.. csik-usage-start


.. _csik-usage-section:

Usage
-----

The F5® |csi_k-long| uses F5 resources to describe how the |csi_k| should configure objects for a  `Kubernetes Service`_ on the BIG-IP.
The F5 resource both directs the |csi_k| to apply configurations to the BIG-IP and ties those configurations to the Service.

.. important::

    * The Kubernetes Service's `ServiceType <http://kubernetes.io/docs/user-guide/services/#publishing-services---service-types>`_ must be "NodePort". This exposes the same port number on each node in the cluster for the service port, allowing the BIG-IP to connect to the service from outside the cluster.
    * An F5 ``virtualServer`` resource defines a virtual server on the BIG-IP for one (1) port, associated with one (1) `Kubernetes Service`_. *You must create a separate F5 resource for each Service port you wish to expose to the BIG-IP.*

An F5 resource must be encoded as a Kubernetes  `ConfigMap`_ that includes the following:

    * ``f5type`` label: tells ``f5-k8s-controller`` what type of F5 resource will be created on the BIG-IP.
    * ``schema`` property: tells ``f5-k8s-controller`` how to correctly verify the content in the ``data`` property.
    * ``data`` property: contains the F5 Resource definition that will be passed to the BIG-IP.
    * ``frontend`` property: describes the object to create on the BIG-IP, such as the ``virtualAddress``.
    * ``backend`` property: identifies the `Kubernetes Service`_ that should act as the server pool.

Define an F5 Resource
`````````````````````

F5 resources are defined as JSON blobs, which are included as encoded data in YAML `ConfigMap`_ files. The data provided in the ConfigMap apply configurations to the BIG-IP. The :ref:`Example F5 Resources <csik-example-f5-resources>` demonstrate how each property should be laid out and how they fit together.

.. _csik-config-vs-frontend:

Frontend Property
~~~~~~~~~~~~~~~~~

The frontend property consists of a set of objects that define how to expose a Service on the BIG-IP.
You can use either the :ref:`Standard <csik_config-vs-frontend-vs>` or :ref:`iApp <csik_config-vs-frontend-iapp>` options in this section of the `ConfigMap`_.

.. _csik_config-vs-frontend-vs:

Standard
^^^^^^^^

The standard options for the Frontend property are shown in the table below.

.. include:: /includes/f5-csi_k/ref_config-parameters-frontend-vs-all.rst

.. _csik_config-vs-frontend-iapp:

iApp
^^^^

The iApp options are a completely custom set of parameters, which correspond to the fields in the iApp template you must complete in order to launch the iApp on a BIG-IP. For the ``iappVariables``, you can either name an object that already exists on the BIG-IP, or enter ``/#create_new#`` to have the iApp create a new object.

.. include:: /includes/f5-csi_k/ref_config-parameters-frontend-iapp.rst


.. _csik_config-vs-backend:

Backend Property
~~~~~~~~~~~~~~~~

The backend property identifies the `Kubernetes Service`_ that will make up the server pool.

.. include:: /includes/f5-csi_k/ref_config-parameters-backend.rst

.. _csik-example-f5-resources:

Example F5 Resources
~~~~~~~~~~~~~~~~~~~~

.. rubric:: Standard

.. literalinclude:: /static/f5-csi_k/example-vs-resource.json

.. rubric:: iApp

.. literalinclude:: /static/f5-csi_k/example-vs-resource-iapp.json



.. _csik-create-vs:

Create a Virtual Server with the F5 |csi_k|
```````````````````````````````````````````

#. Create a new file containing the ConfigMap and encoded data.

    .. literalinclude:: /static/f5-csi_k/example-vs-resource.configmap.yaml
        :emphasize-lines: 6-7, 9, 12-22, 25-27


#. Create the F5 resource on the Kubernetes API server with the ``kubectl create`` command:

   .. code-block:: bash

       $ kubectl create -f example-vs-resource.configmap.yaml


Delete a virtual server from the BIG-IP
```````````````````````````````````````

To remove a virtual server for a `Kubernetes Service`_, and all related objects, from the BIG-IP, **remove the ConfigMap** from the Kubernetes API server.

    .. code-block:: bash

        $ kubectl delete configmap example-vs-resource

.. tip::

    * If you temporarily take down a `Kubernetes Service`_, leave the F5 ConfigMap resource in place. This ensures connectivity to the BIG-IP remains in place when the Service comes back up.

    * If you take down a Service and later deploy a new Service **with the same name**, the |csi_k| will apply the F5 resource to the new Service.

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
