# Virtual Server with Host Persistence

These examples demonstrate the use of hostPersistence used to configure persistence in a per-host basis instead in a per-LTM VS basis which is done by the persistenceProfile option, which configures persistence in all host names in the same LTM VS. The hostPersistence option has precedence over persistenceProfile.

## vs-with-hostPersistence-cookiePassive.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of cookiePasssive type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-cookieInsert.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of cookieInsert type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-cookieRewrite.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of cookieRewrite type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-cookieHash.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of cookieHash type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-sourceAddress.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of sourceAddress type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-destinationAddress.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of destinationAddress type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-hash.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of hash type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-carp.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of carp type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-universal.yaml

By deploying this yaml file in your cluster, CIS will create a VS with persist session rule action of universal type in VS Policy on BIG-IP. This is optional to use.

## vs-with-hostPersistence-disable.yaml

By deploying this yaml file in your cluster, the persistence will be disabled for the specified host inside the VS and cookieInsert perist will be created for the other host as specified. This is optional to use.
