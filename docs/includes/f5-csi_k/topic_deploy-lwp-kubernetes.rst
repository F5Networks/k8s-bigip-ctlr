Deploy the F5 |lwp| for Kubernetes
----------------------------------
.. lwp-deploy-guide

Deploying the F5® |lwp| (LWP) in Kubernetes replaces `kube-proxy <http://kubernetes.io/docs/admin/kube-proxy/>`_.
This allows you to annotate a `Kubernetes Service`_ to enable its ClusterIP to be implemented by the |lwp|, while other services retain the basic kube-proxy behavior.

The F5 |lwp| in Kubernetes is composed of two (2) parts:

    #. a privileged service that manages the ``iptables`` rules of the host, and
    #. the proxy that processes service traffic.

The |lwp| should be deployed on every node in your Kubernetes cluster.
The LWP on the same node as the client handles requests and load-balances to the backend pod.
|lwp| creates a virtual server for every `Kubernetes Service`_ in the cluster that has the F5 annotation configured (see :ref:`Create a Virtual Server <add-lwp-kubernetes-services>`).

Prerequisites
`````````````

- A running `Kubernetes`_ cluster.
- ``kubectl`` (the `Kubernetes`_ CLI) installed, and configured with admin access to the cluster.
- The official ``f5-k8s-controller`` and ``f5-kube-proxy`` images; contact your F5 Sales rep or go to `F5 DevCentral <https://devcentral.f5.com/welcome-to-the-f5-beta-program>`_ to request access to the beta program.


.. _install-lwp-kubernetes:

Install |lwp|
`````````````

Add a |lwp| Instance to Every Node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every node in the cluster need to run an instance of LWP.
The steps below demonstrate how to use a Kubernetes `ConfigMap`_ and `DaemonSet <http://kubernetes.io/docs/admin/daemons/>`_ to run one |lwp| per node and apply the same configurations to each LWP instance.

The :dfn:`DaemonSet` ensures one |lwp| runs per node in the Kubernetes cluster.
The :dfn:`ConfigMap` contains the configurations you want to apply to each LWP instance.

#. Specify the |lwp| :ref:`global <lwp-global-config>` and :ref:`orchestration <lwp-orchestration-config>` configurations in a `ConfigMap`_.

    .. note::

        The ``orchestration.kubernetes.config-file`` property in the ConfigMap points to a volume mounted by the |lwp| DaemonSet spec you'll set up in the next step.


    .. literalinclude:: /static/f5-csi_k/example-lwp-configmap.yaml
       :language: yaml
       :emphasize-lines: 12-15

    :download:`example-lwp-configmap.yaml </static/f5-csi_k/example-lwp-configmap.yaml>`


#. Create a Kubernetes `DaemonSet <http://kubernetes.io/docs/admin/daemons/>`_ for the |lwp|.

    .. note::

        * As with most other Kubernetes configurations, this file can be JSON or YAML.
        * In the example DaemonSet shown here, we

            a. use the ConfigMap (set up in the previous step) to configure the |lwp|; AND

            b. mount a volume that provides the :file:`service-ports.json` config file at the path provided in the ConfigMap.


    .. literalinclude:: /static/f5-csi_k/example-lwp-daemonset.yaml
       :language: yaml

    :download:`example-lwp-daemonset.yaml </static/f5-csi_k/example-lwp-daemonset.yaml>`


Edit Pod Manifest(s) to replace kube-proxy with f5-kube-proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For every node in your cluster, edit the static pod manifest file to ensure that kube-proxy supports handoff to LWP.

#. Replace ``kube-proxy`` with the ``f5-kube-proxy`` image in the **container section**.

#. Add the ``proxy-plugin`` volume mount in the **container section**.

#. Add the ``plugin-config`` volume in the **volumes section**.

    .. literalinclude:: /static/f5-csi_k/example-kube-proxy-manifest.yaml
       :language: yaml
       :linenos:
       :emphasize-lines: 10,27-29,40-42

    :download:`example-kube-proxy-manifest.yaml </static/f5-csi_k/example-kube-proxy-manifest.yaml>`



Create a Virtual Server with |lwp|
``````````````````````````````````

.. _add-lwp-kubernetes-services:

Enable the |lwp| for Kubernetes Service(s)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can add an annotation to the service definition file to enable the |lwp| on any `Kubernetes Service`_.
The LWP annotation's values provide the virtual server configuration, similar to the :ref:`Virtual Server section <lwp-virtual-server-config>` of the LWP config file.
Once it has been enabled, |lwp| takes over the virtual IP for the service.
The virtual server created in each LWP uses the configuration values defined in the annotation.

* The ``lwp.f5.com/config.portname`` annotation enables LWP for the Service port named ``portname``.
* The ``lwp.f5.com/config`` annotation enables LWP for all of the Service's ports, except those ports that already have an annotation for the named port.
* Endpoints and destination details should not be included, as they are dynamically assigned by Kubernetes.

.. note::

    If the configuration is not correct, LWP will reject traffic. The error message can be seen in the LWP logs.

* Use the ``kubectl annotate`` command to annotate an existing service:

    .. code-block:: bash

        kubectl annotate service my-service \
          lwp.f5.com/config.http='{"ip-protocol":"http","load-balancing-mode":"round-robin"}'

* Create a new Service with the F5 annotation incorporated:

    .. rubric:: The example below shows the F5 annotation string incorporated into a sample Service definition.

    .. literalinclude:: /static/f5-csi_k/example-service-lwp.yaml

    :download:`example-service-lwp.yaml </static/f5-csi_k/example-service-lwp.yaml>`


.. toctree::
    :hidden:

    self
