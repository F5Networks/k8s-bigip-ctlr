.. csv-table:: Standard Frontend options (scroll for more)
    :header: Property, Type, Required, Default, Description, Allowed Values

    ``partition``, string, Required, , BIG-IP partition in which to create virtual server objects,
    ``mode``, string, Required, , Proxy mode, "``http``, ``tcp``"
    ``balance``, string, Required, ``round-robin``, Load-balancing mode, ``round-robin``
    ``virtualAddress``, JSON object, Required, , virtual address on the BIG-IP,
    | ``bindAddr``, string, Required, , virtual IP address,
    | ``port``, integer, Required, , port number,
    ``sslProfile``, JSON object, Optional, , Existing SSL profile on BIG-IP to use to access virtual server,
    | ``f5ProfileName``, string, Optional, , "Name of the SSL profile; uses format 'partition_name/cert_name' (e.g., 'Common/testcert')",
