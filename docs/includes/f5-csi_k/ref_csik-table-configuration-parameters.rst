.. list-table:: Configuration Parameters
    :header-rows: 1

    * - Name
      - Description
      - Default Setting
    * - ``--bigip-partition``
      - partition where BIG-IP objects will be configured
      - velcro
    * - ``--bigip-password``
      - admin password for the BIG-IP
      - N/A
    * - ``--bigip-url``
      - admin IP address for the BIG-IP
      - N/A
    * - ``--bigip-username``
      - admin username for the BIG-IP
      - N/A
    * - ``--kubeconfig``
      - path to the *kubeconfig* file
      - N/A
    * - ``--namespace``
      - kubernetes namespace to watch
      - default
    * - ``--python-basedir``
      - directory location of python utilities
      - /app/python
    * - ``--running-in-cluster``
      - flag indicating if the controller was started by k8s
      - true
    * - ``--use-node-internal``
      - flag to filter Kubernetes InternalIP addresses for pool members
      - true
