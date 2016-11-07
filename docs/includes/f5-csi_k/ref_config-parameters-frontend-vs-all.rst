.. list-table:: Frontend - Standard Options
    :header-rows: 1
    :widths: 10 10 10 10 20

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


.. list-table:: SSL Profile Options
    :header-rows: 1
    :widths: 20 20 20 20

    * - Property
      - Description
      - Type
      - Required
    * - ``f5ProfileName``
      - Existing SSL Profile on BIG-IP
      - String
      - Required

.. list-table:: Virtual Address Options
    :header-rows: 1
    :widths: 20 20 20 20

    * - Property
      - Description
      - Type
      - Required
    * - ``bindAddr``
      - Virtual IP address
      - String
      - Required
    * - ``port``
      - Port number
      - Number
      - Required
