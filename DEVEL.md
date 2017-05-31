# Managing vendors

Dependencies are managed with godep.
For details, see https://github.com/tools/godep

If you just want to build, or make changes that don't affect dependencies, there is nothing special to do.

If your change to modify dependencies, you will need to deal with godep. In general, you will want to:

1. godep restore - This will put all your dependencies into $GOPATH
2. rm -rf vendor - Get rid of the saved vendors, so builds will only use $GOPATH.
3. install/upgrade deps. Build / test
4. make godep-save - Save the dependencies that are used by the project.
5. Git diff on 

## Gotchas

When building locally, go will find dependencies first in vendor, then in
$GOPATH/src. This may cause issues because packages in vendor and $GOPATH are
different. If this happens, you might see errors like this:

```
pkg/aspen/controller.go:127: cannot use a.clientset (type *"aspen/vendor/k8s.io/client-go/kubernetes".Clientset) as type "k8s.io/client-go/kubernetes".Interface in argument to informers.NewSharedInformerFactory:
    *"aspen/vendor/k8s.io/client-go/kubernetes".Clientset does not implement "k8s.io/client-go/kubernetes".Interface (wrong type for Apps method)
        have Apps() "aspen/vendor/k8s.io/client-go/kubernetes/typed/apps/v1beta1".AppsV1beta1Interface
        want Apps() "k8s.io/client-go/kubernetes/typed/apps/v1beta1".AppsV1beta1Interface
```

Here a new dependency was added to the code, and added to GOPATH, but the
vendor directory wasn't removed. That new dependency also imported
k8s.io/client-go/kubernetes/typed/apps/v1beta1, but since that package wasn't
in vendor it satisfied that import with the version of the package that was in
$GOAPTH.


