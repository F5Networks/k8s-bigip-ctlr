title
=====

Overview
--------

The F5® FlowPoint™ Proxy controller for `Kubernetes <http://kubernetes.io/>`_ enables the use of the |fpp| in Kubernetes.

The |fppc| runs as a Docker container in Kubernetes. It watches applications being created and destroyed; when an application with the proper labels is created, a new |fpp| for that application is created and scaled to have the requested number of tasks.

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