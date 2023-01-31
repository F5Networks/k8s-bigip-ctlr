# Virtual Server with named port

This section demonstrates the option to configure virtual server with servicePort with either service port name or named targetPort of service. 
servicePort can be either port of the service listening on, service port name or targetPort defined on service. 


Option which can be used to configure is :
    `servicePort`

## virtual-with-service-port-name.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server with endpoints matching service port name defined in virtual server.

## virtual-with-target-port-name.yaml

By deploying this yaml file in your cluster, CIS will create a Virtual Server with endpoints matching target port name defined in virtual server.
