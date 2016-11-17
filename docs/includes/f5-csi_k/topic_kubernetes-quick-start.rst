Introduction
------------

.. include:: /includes/f5-csi_k/topic_csi-controller-kubernetes.rst
    :start-after: csik-overview-body-start
    :end-before: csik-overview-body-end

.. include:: /includes/f5-lwp/concept_lwp-deploy-guide-overview.rst

Prerequisites
-----------------------------

- Licensed, operational `BIG-IP`_ :term:`device`.
- Knowledge of BIG-IP `system configuration`_ and `local traffic management`_.
- Administrative access to the BIG-IP.
- A partition configured on the BIG-IP named *guestbook*
- A running `Kubernetes`_ cluster.
- ``kubectl`` (the `Kubernetes`_ CLI) installed.
- A `Git client <https://git-scm.com>`_ (CLI or GUI)
- The official f5-k8s-controller and f5-kube-proxy images; contact your F5 Sales rep or go to F5 DevCentral to request access to the beta program.

Add a Kubernetes Image Secret
------------------------------------

In order for the `Kubernetes`_ cluster to download and use the F5® |csi_k| and |lwp| images, we must first add a secret to the cluster. The `secret <http://kubernetes.io/docs/user-guide/secrets/>`_ provides the required credentials for the `Docker`_ daemon on each node to be able to download the required F5 container images. Both the |csi_k| and |lwp| images will live in the *kube-system* `namespace <http://kubernetes.io/docs/user-guide/namespaces/>`_.

The following YAML file is used to create the secret:

.. literalinclude:: /static/f5-csi_k/quickstart-k8s-docker-hub-secrets.yaml

:download:`quickstart-k8s-docker-hub-secrets.yaml </static/f5-csi_k/quickstart-k8s-docker-hub-secrets.yaml>`

Next, add the secret with the kubectl:

.. code:: bash

  $ kubectl create -f quickstart-k8s-docker-hub-secrets.yaml

Deploy F5 |csi_k-long|
------------------------------

The |csi_k| image is installed into a `Kubernetes`_ cluster with a `Kubernetes Deployment`_. The following deployment file will ensure that there is one Pod running the f5-k8s-controller image to integrate with your `BIG-IP`_.

.. tip::

  Change the highlighted lines in the following example to match those of your `BIG-IP`.

.. literalinclude:: /static/f5-csi_k/quickstart-f5-k8s-controller.yaml
  :emphasize-lines: 23, 25, 27

:download:`quickstart-f5-k8s-controller.yaml </static/f5-csi_k/quickstart-f5-k8s-controller.yaml>`

The deployment can now be created via kubectl:

.. code:: bash

  $ kubectl create -f quickstart-f5-k8s-controller.yaml
  deployment "f5-k8s-controller" created

You can verify the f5-k8s-controller has been deployed to a pod with the following command:

.. code:: bash

  $ kubectl get pods -l app=f5-k8s-controller --namespace kube-system
  NAME                                   READY     STATUS         RESTARTS   AGE
  f5-k8s-controller-3184671219-s1ldo     0/1       Running        0          34s

Deploy the F5 |lwp|
------------------------------

The |lwp| runs on each node in a cluster and handles requests and load-balances to the correct pod for each `Kubernetes Service`_ configured to use it.

A `DaemonSet <http://kubernetes.io/docs/admin/daemons/>`_  is used to ensure a copy of the |lwp| is running on each node and a `ConfigMap`_ is what the |lwp| uses to obtain it's configuration information.

#. Specify the global configuration for the |lwp|

    .. literalinclude:: /static/f5-csi_k/example-lwp-configmap.yaml

    :download:`example-lwp-configmap.yaml </static/f5-csi_k/example-lwp-configmap.yaml>`

#. Specify a `Kubernetes Daemonset`_

    .. literalinclude:: /static/f5-csi_k/quickstart-lwp-daemonset.yaml

    :download:`quickstart-lwp-daemonset.yaml </static/f5-csi_k/quickstart-lwp-daemonset.yaml>`

#. Use kubectl to deploy and configure the |lwp|

    .. code:: bash

      $ kubectl create -f example-lwp-configmap.yaml
      configmap "lwp-config" created
      $ kubectl create -f quickstart-lwp-daemonset.yaml
      daemonset "lightweight-proxy" created

#. Verify that the |lwp| pods are running:

    .. code:: bash

      kubectl get pods -l name=lightweight-proxy --namespace kube-system
      NAME                      READY     STATUS    RESTARTS   AGE
      lightweight-proxy-f0tt9   1/1       Running   0          5m
      lightweight-proxy-gt0i2   1/1       Running   0          5m
      lightweight-proxy-l4swr   1/1       Running   0          5m
      lightweight-proxy-p5uit   1/1       Running   0          5m

Configure kubernetes pods to use the |lwp|
---------------------------------------------

The f5-kube-proxy runs on each node in a `Kubernetes`_ cluster and replaces the default kube-proxy. The f5-kube-proxy handoff to LWP to provide TCP and HTTP load balancing and forwarding on each node for any `Kubernetes`_ service annotated with the correct syntax, as we will see later.

Edit Pod Manifest(s) to replace kube-proxy with f5-kube-proxy
`````````````````````````````````````````````````````````````
The following can be used to replace the default kube-proxy manifest file typically located at /etc/kubernetes/kube-proxy.yaml on each `Kubernetes`_ node.

.. literalinclude:: /static/f5-csi_k/quickstart-kube-proxy.yaml
  :emphasize-lines: 13

:download:`quickstart-kube-proxy.yaml </static/f5-csi_k/quickstart-kube-proxy.yaml>`

Ensure that kube-proxy pods are up and running after updating the manifest file on each node and looking for the kube-proxy-*<node_ip>* entries from the `Kubernetes`_ pod list:

.. code:: bash

  kubectl get pods --namespace kube-system
  NAME                                   READY     STATUS    RESTARTS   AGE
  f5-k8s-controller-1659257167-ftfx9     1/1       Running   0          1h
  heapster-v1.2.0-4088228293-05kbm       2/2       Running   2          4d
  kube-apiserver-172.17.4.101            1/1       Running   1          4d
  kube-controller-manager-172.17.4.101   1/1       Running   1          4d
  kube-dns-v20-tw5b2                     3/3       Running   3          4d
  kube-proxy-172.17.4.101                1/1       Running   1          4d
  kube-proxy-172.17.4.201                1/1       Running   2          3m
  kube-proxy-172.17.4.202                1/1       Running   2          4m
  kube-proxy-172.17.4.203                1/1       Running   3          13m

Now the F5® |csi_k-long| is configured and ready to use in our `Kubernetes`_ cluster.

Deploy the Kubernetes Guestbook Demo app
------------------------------------------------

The `Guestbook example <https://github.com/kubernetes/kubernetes/tree/master/examples/guestbook-go>`_ application is a simple multi-tier web app we will use to test the |csi_k-long| intergration. The application front-end is build in Go and uses Redis for it's data storage backend.

|csi| will integrate with the web front-end and provide access to the Go app for clients external to the `Kubernetes`_ cluster. |lwp| will be configured to direct traffic to the Redis master and slaves.

Download the Guestbook example
`````````````````````````````

The example application lives within the `Kubernetes` Github repository, so we must first clone a copy to our local workstation:

    .. code:: bash

      $ git clone https://github.com/kubernetes/kubernetes.git
      $ cd kubernetes/

Define the Guestbook service
```````````````````````````

The Guestbook app uses a `Kubernetes`_ service to expose the frontend application to external clients. It's current configuration JSON configuration needs to be modified to have it correctly integrate with the |csi|.

Edit the examples/guestbook-go/guestbook-service.json file the text "LoadBalancer" with "NodePort" highlighted in the following example as shown:

.. literalinclude:: /static/f5-csi_k/quickstart-guestbook-service.json
    :emphasize-lines: 20

:download:`quickstart-guestbook-service.json </static/f5-csi_k/quickstart-guestbook-service.json>`

Deploy the Guestbook Datastore service
`````````````````````````````````````

The next step is to deploy the entire Guestbook application within the cluster:

    .. code:: bash

      $kubectl create -f examples/guestbook-go/
      replicationcontroller "guestbook" created
      service "guestbook" created
      replicationcontroller "redis-master" created
      service "redis-master" created
      replicationcontroller "redis-slave" created
      service "redis-slave" created

      With the application deployed, the next steps are to enable the |lwp| and |csi| integrations.

Configure Redis slave service to use |lwp|
`````````````````````````````````````````

We will now annotate the 'redis-slave' service to enable the |lwp|. Once it has been enabled, |lwp| will control the virtual IP for the 'redis-slave' service.

Seeing as Redis uses a TCP based protocol, will ensure the ip-protocol for the annotation is set to 'tcp':

    .. code:: bash

        $ kubectl annotate service redis-slave \
          lwp.f5.com/config='{"ip-protocol":"tcp","load-balancing-mode":"round-robin"}'
          service "redis-slave" annotated

Our redis-slave service will now be load balanced by the |lwp| within the `kubernetes`_ environment across all nodes.

Configure |csi_k| for the Guestbook front-end
````````````````````````````````````````````

The final step is to have the |csi_k| integrate with the Guestbook front-end to provide North-South load balancing.

.. literalinclude:: /static/f5-csi_k/quickstart-guestbook_f5_configmap.yaml
  :emphasize-lines: 22-23

:download:`quickstart-guestbook_f5_configmap.yaml </static/f5-csi_k/quickstart-guestbook_f5_configmap.yaml>`

.. tip::

    Make sure the highlighted lines are configuration for an IP address and port available on your BIG-IP.

To verify that the |csi| is indeed working, use kubectl to determin the name the of the f5-k8s-controller pod:

.. code:: bash

     kubectl get po --namespace kube-system
     NAME                                   READY     STATUS    RESTARTS   AGE
     f5-k8s-controller-1659257167-ftfx9     1/1       Running   0          1h

Next, kubectl can be used tail the pod's logs to verify that the Configmap was picked up correctly and a configuraiton created and sent to the `BIG-IP`_:

.. code:: bash

    kubectl logs f5-k8s-controller-1659257167-ftfx9 --namespace kube-system --tail 10
    2016/11/08 00:30:12 [INFO] [2016-11-08 00:30:12,869 marathon_lb INFO] Generating config for BIG-IP from Kubernetes state
    2016/11/08 00:30:12 [INFO] Wrote 1 Virtual Server configs to file /tmp/f5-k8s-controller.config.1.json

The |csi_k| integration can be confirmed by logging into your `BIG-IP`_ and looking at the Virtual Server list under the *k8s* partition to see the newly configured virtual server.
