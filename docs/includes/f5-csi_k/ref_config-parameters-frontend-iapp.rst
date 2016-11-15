.. csv-table:: iApp Frontend options (scroll for more)
    :header: Property, Type, Required, Default, Description, Allowed Values

    ``partition``, string, Required, , BIG-IP partition in which to create virtual server objects,
    ``iapp``, string, Required, , Existing BIG-IP iApp template to use to create the application service,
    ``iappTableName``, string, Required, , iApp table entry that specifies pool members,
    ``iappOptions``, key-value object, Required, , configuration options to be applied to the application service,
    ``iappVariables``, key-value object, Required, , defines variables the iApp needs to create the Service,

