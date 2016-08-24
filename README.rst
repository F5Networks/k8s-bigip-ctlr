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

Configure the controller using the environment variables shown in the table.

FIXME(garyr): Update this list as appropriate.
+-----------------------------------+---------------------------------------------------+-----------------------+
| Name                              | Description                                       | Default               |
+===================================+===================================================+=======================+
| LWP_ENABLE_LABEL                  | label used to determine LWP requirements          | f5-lwp                |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_CPU                   | amount of CPU for LWP tasks                       | 1.0                   |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_MEM                   | amount of memory for LWP tasks                    | 256.0                 |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_STORAGE               | amount of memory for LWP tasks                    | 0                     |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_COUNT_PER_APP         | number of LWP tasks per application               | 1                     |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_CONTAINER             | location of docker image to pull                  | f5networks/lwp        |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_CONTAINER_PORT        | container port to expose                          | 8000                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_URIS                  | comma separated list of URIs to pass to Marathon  | EMPTY                 |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_VS_KEEP_ALIVE         | Virtual server keep alive, in msecs               | 1000                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_VS_PROTOCOL           | protocol for virtual server (http or tcp)         | http                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_STATS_URL             | Url for sending stats                             | None                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_STATS_TOKEN           | Stats authentication token                        | None                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_STATS_FLUSH_INTERVAL  | Stats flush intercal, in msecs                    | 10000                 |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_STATS_BACKEND         | Stats backend type, (for example, splunk)         | None                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_FORCE_PULL            | Sets Marathon to force pull at LWP start-up       | true                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_ENV_PREFIX                    | prefix for env variables to pass to the LWP       | \LWP_ENV_             |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_LOG_LEVEL             | logging level                                     | INFO                  |
+-----------------------------------+---------------------------------------------------+-----------------------+
| LWP_DEFAULT_VS_FLAGS              | flags for configuring LWP behavior [#]_           |  {}                   |
+-----------------------------------+---------------------------------------------------+-----------------------+

.. [#] Only bools (true or false) are permitted.

Example
~~~~~~~

Usually, the controller is deployed by Kubernetes. The example below shows how it can be run from the command-line. **This example is provided for enhanced understanding, not as a recommendation.**

FIXME(garyr): Add correct example
.. topic:: Example

    .. code-block:: shell

        docker run -it -d -e MARATHON_URL="http://172.28.128.3:8080" -e LWP_ENABLE_LABEL lwp-myapp -e LWP_DEFAULT_CONTAINER f5networks/lwp f5velcro/f5-k8s-controller

    Then, create your application in the Marathon instance running at 172.28.128.3 and label it with the label ``lwp-myapp:enable``.

    The controller will create a new application in your Kubernetes cluster to be the LWP for your application.

Override Controller Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Default values configured for the LWP Controller can be modified on a per-app basis. The following labels, which can be applied to the application being controlled, override the corresponding LWP Controller default value.

+-----------------------------------+---------------------------------------------------+
| Name                              | Description                                       |
+===================================+===================================================+
| LWP_VS_KEEP_ALIVE                 | | overrides LWP_DEFAULT_VS_KEEP_ALIVE             |
+-----------------------------------+---------------------------------------------------+
| LWP_VS_PROTOCOL                   | | overrides LWP_DEFAULT_VS_PROTOCOL               |
+-----------------------------------+---------------------------------------------------+
| LWP_LOG_LEVEL                     | | overrides LWP_DEFAULT_LOG_LEVEL                 |
+-----------------------------------+---------------------------------------------------+
| LWP_STATS_URL                     | | overrides LWP_DEFAULT_STATS_URL                 |
+-----------------------------------+---------------------------------------------------+
| LWP_STATS_TOKEN                   | | overrides LWP_DEFAULT_STATS_TOKEN               |
+-----------------------------------+---------------------------------------------------+
| LWP_STATS_FLUSH_INTERVAL          | | overrides LWP_DEFAULT_STATS_FLUSH_INTERVAL      |
+-----------------------------------+---------------------------------------------------+
| LWP_STATS_BACKEND                 | | overrides LWP_DEFAULT_STATS_BACKEND             |
+-----------------------------------+---------------------------------------------------+
| LWP_FORCE_PULL                    | | overrides LWP_DEFAULT_FORCE_PULL                |
+-----------------------------------+---------------------------------------------------+
| LWP_CPU                           | | overrides LWP_DEFAULT_CPU                       |
+-----------------------------------+---------------------------------------------------+
| LWP_MEM                           | | overrides LWP_DEFAULT_MEM                       |
+-----------------------------------+---------------------------------------------------+
| LWP_STORAGE                       | | overrides LWP_DEFAULT_STORAGE                   |
+-----------------------------------+---------------------------------------------------+
| LWP_COUNT_PER_APP                 | | overrides LWP_DEFAULT_COUNT_PER_APP             |
+-----------------------------------+---------------------------------------------------+
| LWP_CONTAINER                     | | overrides LWP_DEFAULT_CONTAINER                 |
+-----------------------------------+---------------------------------------------------+
| LWP_URIS                          | | overrides LWP_DEFAULT_URIS                      |
+-----------------------------------+---------------------------------------------------+
| LWP_VS_FLAGS                      | | merges with and overrides collisions on         |
|                                   | | LWP_DEFAULT_VS_FLAGS                            |
+-----------------------------------+---------------------------------------------------+

Configuring the LWP
-------------------

**not yet implemented**

To configure LWP, use the ``LWP_CONFIG`` label with a JSON file containing the desired configuration. See the `traffic-director-proxy documentation <https://bldr-git.int.lineratesystems.com/velcro/traffic-director-proxy>`_ for details.

.. note::

    - Values specified in this config file **will not be overwritten** by the LWP Controller.
    - Specifying the app name and port might lead to misconfiguration or unexpected behavior. Avoid this in general. There are no known use cases yet for specifying these.

The LWP Traffic Director Controller (TDC) can also pass through environment variables with additional configuration options. To pass configurations through to the LWP, add application labels using the ``LWP_ENV_PREFIX``.

Example
~~~~~~~

To pass through the environment ``TEST=test``, add this label to your application:

.. code-block:: shell

    LWP_ENV_TEST:test


Any of the ``LWP_DEFAULT_*`` environment variables can also be overridden by adding a label.

.. topic:: Example:

    To override the ``LWP_DEFAULT_CPU`` in the TEST environment and set it to 2.3:

    .. code-block:: shell

        LWP_ENV_TEST_LWP_CPU:2.3


Known Limitations
-----------------

-  Changes to ``LWP_ENABLE_LABEL`` cause the controller to start controlling a new set of apps which have the new value as a label. All apps with the old label will be ignored. Since the controller is stateless with respect to Marathon it needs to be this way. An easy way to avoid this problem is to never change the ``LWP_ENABLE_LABEL`` of an existing controller. Always just destroy the controller and create a new one. This way there is no confusion or expectation of a different behavior.

-  More than one Mesos agent is required. By default, Marathon's restart policy starts a new instance of the app being modified before killing the old version. When there is only one agent, the LWP reserves a port on that agent; then, when there is a configuration modification, a new version cannot be started. This will be addressed in a future version by permitting Marathon's restart policy to be configurable on a per controller or per app basis.

.. |build status| image:: https://bldr-git.int.lineratesystems.com/velcro/f5-k8s-controller/badges/master/build.svg
   :target: https://bldr-git.int.lineratesystems.com/velcro/f5-k8s-controller/commits/master
