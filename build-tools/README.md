# Introduction
This directory contains helper scripts which automates various steps used
during product development.

## Import-Packages
This script automates the following steps:
* Determines vendor dependencies of a package.
* Figures out the external repositories associated with these dependencies.
* Looks for mirrors of those dependencies in the Gitlab mirror namespace
  supplied by the user. It looks for projects with exact name match.
  If a project doesn't exist in mirror, a new project is created in
  namespace with import-url of the external repository of the dependency.
* Determines the currently existing submodules and if a submodule exists with
  the import dependency path it is skipped. If a submodule doesn't exist, it is
  added from the mirrored repository in the '$PWD/vendor/src' path with correct
  import path dependency satisfied.

### Caveats
This script uses 'go list' commands which only work with a particular directory
structure. Layout of the workspace has to be the following:
WORKDIR/src/"package\_name"
In the above structure this script should be invoked from WORKDIR and
"package\_name" should be a directory under WORKDIR/src which contains all go
files related to the package whose vendor dependencies have to be determined.

### Requirements
This script uses python gitlab API module called gitlab. Follow the instructions
here: https://github.com/gpocentek/python-gitlab to install the module.

### Limitations
To enable CI builds to work correctly, mirrored projects need to deploy
gitlab-ci "Deploy Key" which is not supported by this script.
