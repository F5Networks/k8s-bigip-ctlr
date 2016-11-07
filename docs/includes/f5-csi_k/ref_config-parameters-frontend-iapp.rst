.. _csik_config-vs-frontend-iapp:

.. list-table:: Frontend iApp Configuration
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
    * - ``iapp``
      - The iApp template to use to create the application service
      - String
      - Required
      - Must already exist on BIG-IP
    * - ``iappTableName``
      - The iApptable entry that specifies pool members
      - String
      - Required
      - 
    * - ``iappOptions``
      - Configuration options to apply to the application service
      - Key-Value Object
      - Required
      - 
    * - ``iappVariables``
      - Defines the variables the iApp needs to create the Service
      - Key-Value Object
      - Required
      - 

