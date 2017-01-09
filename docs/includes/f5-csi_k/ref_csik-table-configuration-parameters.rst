.. list-table:: Configuration Parameters
    :header-rows: 1

    * - Name
      - Description
      - Default Setting
    * - ``--bigip-partition``
      - partition(s) to configure BIG-IP objects in
      - N/A
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
      - flag indicating if k8s started the controller
      - true
    * - ``--use-node-internal``
      - flag to filter Kubernetes InternalIP addresses for pool members
      - true
    * - ``--verify-interval``
      - interval at which to verify the BIG-IP configuration
      - 30 (seconds)
    * - ``--log-level``
      - Logging level: INFO, DEBUG, CRITICAL, WARNING, or ERROR
      - INFO
