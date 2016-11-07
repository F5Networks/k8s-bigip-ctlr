.. _csik_config-vs-frontend-vs:

.. list-table:: Frontend Standard Config Parameters
    :header-rows: 1

    * - Property
      - Description
      - Type
      - Required
      - Notes
    * - ``partition``
      - BIG-IP partition to use
      - String
      - Required
      - Must be configured on f5-k8s-controller
    * - ``mode``
      - Proxy mode
      - String
      - Required
      - Valid values: "tcp", "http"
    * - ``balance``
      - Load-balancing mode
      - String
      - Required
      - Valid values: "round-robin"
    * - ``sslProfile``
      - Name of SSL Profile to use
      - :ref:`SSL Profile <csik_config-vs-frontend-vs-sslProfile>`
      - Optional
      - Must already exist on BIG-IP
    * - ``virtualAddress``
      - Virtual Address on BIG-IP 
      - :ref:`Virtual Address <csik_config-vs-frontend-vs-virtualAddress>`
      - Required
      - 

