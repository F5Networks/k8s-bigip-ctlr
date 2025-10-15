# Upgrading from Cluster-wide RBAC to Namespaced RBAC

## Overview

When upgrading F5 BIG-IP Controller and switching from cluster-wide RBAC (`rbac.namespaced: false`) to namespaced RBAC (`rbac.namespaced: true`), you need to manually clean up the old cluster-wide RBAC resources to maintain the principle of least privilege.

## Why Manual Cleanup is Required

Helm does not automatically remove resources when their conditional statements change. When you switch to namespaced RBAC:

- **Old resources persist**: The original ClusterRole and ClusterRoleBinding remain in the cluster
- **New resources are created**: Namespaced Roles/RoleBindings and minimal ClusterRole are created  
- **Security concern**: The controller retains broader permissions than intended
- **Resource clutter**: Unused RBAC resources remain in the cluster

## Pre-Upgrade Cleanup Steps

### 1. Identify Resources to Clean Up

Before upgrading, identify the current cluster-wide RBAC resources:

```bash
# Replace <release-name> with your actual Helm release name
RELEASE_NAME="<release-name>"

# List current ClusterRole
kubectl get clusterrole | grep $RELEASE_NAME

# List current ClusterRoleBinding  
kubectl get clusterrolebinding | grep $RELEASE_NAME
```

### 2. Backup Current RBAC Configuration (Optional)

```bash
# Backup ClusterRole
kubectl get clusterrole $RELEASE_NAME -o yaml > clusterrole-backup.yaml

# Backup ClusterRoleBinding
kubectl get clusterrolebinding $RELEASE_NAME -o yaml > clusterrolebinding-backup.yaml
```

### 3. Clean Up Old Resources

**Important**: Perform this cleanup BEFORE upgrading to avoid permission conflicts.

```bash
# Delete ClusterRoleBinding first to avoid permission issues
kubectl delete clusterrolebinding $RELEASE_NAME

# Delete ClusterRole
kubectl delete clusterrole $RELEASE_NAME
```

### 4. Upgrade with Namespaced RBAC

```bash
# Upgrade with namespaced RBAC enabled
helm upgrade $RELEASE_NAME f5networks/f5-bigip-ctlr \
  --set rbac.namespaced=true \
  --set args.namespaces='["namespace1","namespace2"]' \
  --set args.bigip_url=<your-bigip-url> \
  [other-parameters]
```

## Post-Upgrade Verification

### 1. Verify Old Resources are Gone

```bash
# Should return no results
kubectl get clusterrole $RELEASE_NAME
kubectl get clusterrolebinding $RELEASE_NAME
```

### 2. Verify New Namespaced Resources

```bash
# Check minimal cluster-scope resources
kubectl get clusterrole ${RELEASE_NAME}-clusterscope
kubectl get clusterrolebinding ${RELEASE_NAME}-clusterscope

# Check namespaced roles (replace with your actual namespaces)
kubectl get role -n namespace1 | grep $RELEASE_NAME
kubectl get rolebinding -n namespace1 | grep $RELEASE_NAME

# If IPAM is enabled, check IPAM namespace permissions
kubectl get role -n kube-system | grep ipam
kubectl get rolebinding -n kube-system | grep ipam
```

### 3. Verify Controller Functionality

```bash
# Check controller pod status
kubectl get pods -n <controller-namespace> | grep $RELEASE_NAME

# Check controller logs for permission errors
kubectl logs -n <controller-namespace> deployment/$RELEASE_NAME
```

## Troubleshooting

### Permission Denied Errors

If you see permission-related errors in the controller logs:

1. **Check namespaces configuration**: Ensure `args.namespaces` includes all required namespaces
2. **Verify IPAM permissions**: If using IPAM, ensure IPAM namespace has proper Role/RoleBinding
3. **Check cluster-scope permissions**: Verify minimal cluster-scope resources were created

### Rolling Back

If you need to revert to cluster-wide RBAC:

```bash
# Upgrade back to cluster-wide RBAC
helm upgrade $RELEASE_NAME f5networks/f5-bigip-ctlr \
  --set rbac.namespaced=false \
  [other-parameters]
  
# Clean up namespaced resources if needed
kubectl delete role $RELEASE_NAME-namespace1 -n namespace1
kubectl delete rolebinding $RELEASE_NAME-namespace1 -n namespace1
# Repeat for other namespaces
```

## IPAM Considerations

When using IPAM with namespaced RBAC:

- IPAM CRs are created in the namespace specified by `--ipam-namespace` (defaults to `kube-system`)
- Ensure the `args.ipam_namespace` value in your Helm values matches your CIS configuration
- The chart automatically creates appropriate IPAM namespace permissions

## Example Complete Upgrade Process

```bash
# 1. Set variables
RELEASE_NAME="my-f5-controller"
NAMESPACES='["app1","app2","app3"]'
BIGIP_URL="https://192.168.1.100"

# 2. Backup and clean up old resources
kubectl get clusterrole $RELEASE_NAME -o yaml > clusterrole-backup.yaml
kubectl get clusterrolebinding $RELEASE_NAME -o yaml > clusterrolebinding-backup.yaml
kubectl delete clusterrolebinding $RELEASE_NAME
kubectl delete clusterrole $RELEASE_NAME

# 3. Upgrade to namespaced RBAC
helm upgrade $RELEASE_NAME f5networks/f5-bigip-ctlr \
  --set rbac.namespaced=true \
  --set args.namespaces=$NAMESPACES \
  --set args.bigip_url=$BIGIP_URL \
  --set args.ipam=true \
  --set args.ipam_namespace=kube-system

# 4. Verify upgrade
kubectl get clusterrole ${RELEASE_NAME}-clusterscope
kubectl get role -A | grep $RELEASE_NAME
kubectl logs -n kube-system deployment/$RELEASE_NAME
```

## Security Benefits

After successful migration to namespaced RBAC:

- **Principle of least privilege**: Controller only has permissions for specified namespaces
- **Reduced attack surface**: No cluster-wide permissions for most resources
- **Better compliance**: Easier to audit and meet security requirements
- **Namespace isolation**: Clear boundary of controller permissions

## Additional Resources

- [F5 CIS RBAC Documentation](https://clouddocs.f5.com/containers/latest/userguide/kubernetes/#cis-installation)
- [Kubernetes RBAC Best Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Helm Upgrade Documentation](https://helm.sh/docs/helm/helm_upgrade/)
