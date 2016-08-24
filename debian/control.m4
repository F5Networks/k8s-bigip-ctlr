# Source package
Source: f5-k8s-controller`'m4_BUILD_NAME_EXT`'
Section: non-free/f5
Priority: optional
Maintainer: Gary Ritzer <g.ritzer@f5.com>
Build-Depends: debhelper (>= 9), golang-go, git-buildpackage
Standards-Version: 3.9.6
Homepage: http://www.f5.com
Vcs-Git: `'m4_VCS_GIT`'
Vcs-Browser: https://bldr-git.int.lineratesystems.com/velcro/f5-k8s-controller
XBCS-Git-Tag: `'m4_GIT_TAG`'
XBCS-Version-Branch: `'m4_VERSION_BRANCH`'

# Binary package
Package: f5-k8s-controller-bin`'m4_BUILD_NAME_EXT`'
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Provides: f5-k8s-controller-bin
Conflicts: f5-k8s-controller-bin`'m4_CONFLICTS_UNOPT`'
Description: Controller for the LWP in Kubernetes
