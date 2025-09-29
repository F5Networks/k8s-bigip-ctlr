## Security recommendations
When configuring Role-Based Access Control (RBAC) in your system, it's crucial to follow kubernetes best practices to ensure the security and integrity of your resources. Here are some key recommendations:

**Principle of Least Privilege**: Always grant the minimum permissions necessary for users or service accounts to perform their tasks. Avoid using overly permissive roles like `cluster-admin` unless absolutely necessary.

**Use Namespaced Roles**: Whenever possible, use namespaced roles instead of cluster-wide roles. This limits the scope of permissions to a specific namespace, reducing the risk of unintended access.

Refer to the [Namespaced RBAC](./Namespaced-RBAC/README.md) example for guidance on creating namespaced roles and role bindings.

Use [ClusterRoles](./clusterrole.yaml) if you need to watch all namespaces.


