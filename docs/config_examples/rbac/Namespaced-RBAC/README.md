## Documentation to create Namespaced RBAC for CIS

CIS manages few cluster scoped resources like `nodes', 'namespaces', 'customresourcedefinitions', 'blockaffinities' etc.For these resources we need to create ClusterRole and ClusterRoleBinding.
For all other resources we can create Role and RoleBinding for all the CIS watched namespaces.

### Create ClusterRole and ClusterRoleBinding for CIS

[cluster_rbac.yaml](./cluster_rbac.yaml) file contains the ClusterRole and ClusterRoleBinding for CIS.

### Create Role and RoleBinding for all CIS watched namespaces.
[namespace_rbac.yaml](./namespace_rbac.yaml) file contains the Role and RoleBinding that can be created  for namespace. Use this to create Role and RoleBinding for all the namespaces that CIS is watching.

### Create Secret role rbac for CIS to access secrets in additional namespaces
CIS supports referencing secrets in additional namespaces like cis deployment namespace for configuring bigip credentials or for referencing TLS secrets across namespaces.You can tune this by creating secret rbac for additional namespaces required
[secret_rbac.yaml](./secret_role_namespace_rbac.yaml) file contains the secret Role and RoleBinding that can be created  for namespace . Use this to create Role and RoleBinding for additional namespaces other than cis watched namespaces where secret reference is used.

### Create Role and RoleBinding for CIS to access configmaps in additional namespaces
CIS supports referencing configmaps in additional namespaces like cis deployment namespace for configuring global config like multicluster requirements.You can tune this by creating configmap rbac for additional namespaces required
[configmap_rbac.yaml](./configmap_namespace_rbac.yaml) file contains the configmap Role and RoleBinding that can be created  for namespace . Use this to create Role and RoleBinding for additional namespaces other than cis watched namespaces where configmap reference is used.