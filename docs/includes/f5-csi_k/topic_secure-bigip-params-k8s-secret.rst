.. _kubernetes-secret-bigip-login:

Store BIG-IP Credentials in a Kubernetes Secret
```````````````````````````````````````````````

`Kubernetes`_ `Secrets <http://kubernetes.io/docs/user-guide/secrets/>`_ can be used to keep your BIG-IP admin credentials, and other sensitive information, secure. This information can be pulled into the Deployment configuration file via the Secret, as shown in the example.

.. important:: Both the Secrets and Deployment configuration files can be either YAML or JSON.

#. Create a new 'secrets' file (for example, :file:`bigip_credentials.YAML`).

    example

#. In a terminal, run the following commands:

    .. code-block:: bash

        echo <YOUR-BIGIP-IPADDRESS> | base64
        echo <YOUR-BIGIP-USERNAME> | base64
        echo <YOUR-BIGIP-PASSWORD> | base64

#. Paste the resulting text into the secrets file in the ``url``, ``username``, and ``password`` fields, respectively.

#. In the Deployment configuration file, add an ``env`` section to the ``container`` blob. Enter the name of your Secrets file as the ``secretKeyRef`` ``name`` parameter.

    .. code-block:: yaml
        :emphasize-lines: 5-7

        env:
        # Pull BIG-IP username, password, and url out of the secret store and put in environment
        - name: BIGIP_USERNAME
          valueFrom:
            secretKeyRef:
              name: bigip-credentials
              key: username
        - name: BIGIP_PASSWORD
          valueFrom:
            secretKeyRef:
              name: bigip-credentials
              key: password
        - name: BIGIP_URL
          valueFrom:
            secretKeyRef:
              name: bigip-credentials
              key: url

#. In the Deployment configuration file, update the ``args`` blob to use your environment variables:

    .. code-block:: yaml
        :emphasize-lines: 2-4

            args: ["--running-in-cluster=true",
              "--bigip-url=$(BIGIP_URL)",
              "--bigip-username=$(BIGIP_USERNAME)",
              "--bigip-password=$(BIGIP_PASSWORD)"
            ]



.. container::

    **Example**

    * Sample BIG-IP credentials file:

    .. literalinclude:: /static/f5-csi_k/sample-bigip-credentials.yaml

    :download:`sample-bigip-credentials.yaml </static/f5-csi_k/sample-bigip-credentials.yaml>`

    * Sample configuration file using Secrets:

    .. literalinclude:: /static/f5-csi_k/sample-f5-k8s-controller.yaml

    :download:`sample-f5-k8s-controller.yaml </static/f5-csi_k/sample-f5-k8s-controller.yaml>`
