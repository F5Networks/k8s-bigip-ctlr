.. _csik_config-vs-backend:

.. list-table:: Backend Virtual Server Config Parameters
    :header-rows: 1

    * - Property
      - Description
      - Type
      - Required
      - Notes
    * - ``serviceName``
      - Kubernetes service that represents the server pool
      - String
      - Required
      - 
    * - ``servicePort``
      - Port number of service port
      - Number
      - Required
      - Matches port in Kubernetes Service
