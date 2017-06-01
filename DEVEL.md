# Managing vendors

Dependencies are managed with godep.
For details, see https://github.com/tools/godep

If you just want to build, or make changes that don't affect dependencies, there is nothing special to do.

If your change to modify dependencies, you will need to deal with godep. CThe In general, you will want to:

1. `make godep-restore` - This will install all your dependencies into $GOPATH, and remove the vendor directory. 
   go build will find the versions of the dependencies in $GOPATH, allowing you to easily modify them
2. Hack. install/upgrade deps with go get. Build/test locally with `make all test`
3. `make godep-save` - Save the dependencies that are used by the project.
4. Git diff Godeps/Godeps.json to see what the dependency changes were, to make sure they are expected.
5. `git add vendor; git commit` - Commit the new vendored versions as its own commit.

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


