Developer README
================

This area is for documents that assist the development team but should not be included in the public-facing documentation.


Configuration
-------------

Configure the controller using the parameters shown in the table.

+----------------------------+----------------------------------------------------------+------------------+
| Name                       | Description                                              | Default          |
+============================+==========================================================+==================+
| --running-in-cluster       | flag indicating if the controller was started by k8s     | true             |
+----------------------------+----------------------------------------------------------+------------------+
| --kubeconfig               | path to the kubeconfig file                              |                  |
+----------------------------+----------------------------------------------------------+------------------+
| --bigip-url                | URL to the Big-IP                                        |                  |
+----------------------------+----------------------------------------------------------+------------------+
| --bigip-username           | User name for logging into the Big-IP                    |                  |
+----------------------------+----------------------------------------------------------+------------------+
| --bigip-password           | Password for logging into the Big-IP                     |                  |
+----------------------------+----------------------------------------------------------+------------------+


Example
~~~~~~~

Usually, the controller is deployed by Kubernetes. The example below shows how it can be run from the command-line. **This example is provided for enhanced understanding, not as a recommendation.**

.. topic:: Example

    .. code-block:: shell

        docker run -it -d f5networks/lwp f5velcro/f5-k8s-controller --kubeconfig=./kubeconfig

    The controller will create a new application in your Kubernetes cluster to be the LWP for your application.

Configuring the LWP
-------------------

**not yet implemented**


Known Limitations
-----------------


