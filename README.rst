Status: |build status|

Lightweight Proxy Controller for Kubernetes
===========================================

.. toctree::
    :hidden:
    :glob:

    self
    Helper Scripts <scripts/README>


Introduction
------------

The lightweight proxy controller for Kubernetes (f5-k8s-controller) is designed to run as a docker container in Kubernetes. It watches applications being created and destroyed. When an application with the proper labels is created, a new LWP for that application is created and scaled to have the requested number of tasks.

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

.. |build status| image:: https://bldr-git.int.lineratesystems.com/velcro/f5-k8s-controller/badges/master/build.svg
   :target: https://bldr-git.int.lineratesystems.com/velcro/f5-k8s-controller/commits/master
