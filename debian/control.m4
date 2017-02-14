# Source package
Source: k8s-bigip-ctlr`'m4_BUILD_NAME_EXT`'
Section: non-free/f5
Priority: optional
Maintainer: Gary Ritzer <g.ritzer@f5.com>
Build-Depends: debhelper (>= 9), golang-go, git-buildpackage
Standards-Version: 3.9.6
Homepage: http://www.f5.com
Vcs-Git: `'m4_VCS_GIT`'
Vcs-Browser: https://bldr-git.int.lineratesystems.com/velcro/k8s-bigip-ctlr
XBCS-Git-Tag: `'m4_GIT_TAG`'
XBCS-Version-Branch: `'m4_VERSION_BRANCH`'

# Binary package
Package: k8s-bigip-ctlr-bin`'m4_BUILD_NAME_EXT`'
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Provides: k8s-bigip-ctlr-bin
Conflicts: k8s-bigip-ctlr-bin`'m4_CONFLICTS_UNOPT`'
Description: Controller for the BIG-IP in Kubernetes
