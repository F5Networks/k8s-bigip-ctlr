F5 |csi_k|
==========

Overview
--------

The F5® |csi| (CSI) for `Kubernetes <http://kubernetes.io/>`_ allows you to provision BIG-IP® Local Traffic Manager™ (LTM®) services using Kubernetes. It works in conjunction with the F5 |fp| ™ proxy to provide North-South and East-West traffic management for containerized applications.

The |csi| runs as a Docker container in Kubernetes. It watches applications being created and destroyed. When an application with the proper labels is created, the |csi| creates a new |fpp| for that application and scales it to have the requested number of tasks.

.. todo:: add how it works (high level)

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