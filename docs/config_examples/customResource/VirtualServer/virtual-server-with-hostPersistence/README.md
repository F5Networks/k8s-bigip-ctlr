# Virtual Server with Host Persistence

This section demonstrates the option to configure persist session rule action at the VS policy level using Host persistence in the BIG IP. 

This is optional to use. Hostpersistence label should be used when there is host in the virtual server CR.

```
#Example
hostPersistence:
  method: cookiePassive
  metaData:
    name: CookiePassiveName
```

## vs-with-hostPersistence.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action in VS Policy on BIG-IP.

This is optional to use.

## vs-with-hostPersistence-disable.yaml
By deploying this yaml file in your cluster, the persistence will be disabled for the specified host inside the VS.
