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
-
-
-


Caveats
-------
-
-
-


Configuration
-------------
.. comment:: list configuration steps below

#.

#.

#.

.. comment:: use the following template to create a table using the list-table format

.. list-table:: Configuration Parameters
    :header-rows: 1

    * - Name
      - Description
      - Default Setting
    * - ``--running-in-cluster``
      - flag indicating if the controller was started by k8s
      - true
    * - ``--kubeconfig``
      - path to the *kubeconfig* file
      - N/A
    * - ``--bigip-url``
      - URL for the BIG-IP
      - N/A
    * - ``--bigip-username``
      - username for the BIG-IP
      - N/A
    * - ``--bigip-password``
      - password for the BIG-IP
      - N/A


Use Kubernetes Secrets to Import BIG-IP parameters
--------------------------------------------------

The BIG-IP parameters can be stored in a Kubernetes secret. The :file:`scripts/sample-bigip-credentials.yaml` file has an example configuration for this purpose. When used in combination with the :file:`scripts/sample-f5-k8s-controller.yaml` configuration file, the command line options to the controller for the BIG-IP are auto-populated from the secret.

Example
~~~~~~~

.. todo:: provide example

.. todo:: provide instructions


Further Reading
---------------
.. comment:: provide links to relevant documentation (BIG-IP, other velcro projects, other docs in this project) here

.. seealso::

    * x
    * y
    * z

.. [#] See `Using Docker Container Technology with F5 Products and Services <https://f5.com/resources/white-papers/using-docker-container-technology-with-f5-products-and-services>`_

.. _ConfigMap: http://kubernetes.io/docs/user-guide/configmap/
