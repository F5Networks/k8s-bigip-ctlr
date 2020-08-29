# How to expose multiple port in services in kubernetes or Multi-Port Services

You have two options:

1. You could have multiple services, one for each port. As you pointed out, each service will end up with a different IP address
    
2. You could have a single service with multiple ports. In this particular case, you must give all ports a name.

For some Services, you need to expose more than one port. Kubernetes lets you configure multiple port definitions on a Service object. When using multiple ports for a Service, you must give all of your ports names so that these are unambiguous. For example:
```
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  selector:
    app: MyApp
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
    - name: https
      protocol: TCP
      port: 443
      targetPort: 6443
```