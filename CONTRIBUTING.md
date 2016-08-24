# Booting a build environment
If you do not already have [Vagrant](https://www.vagrantup.com) installed,
install using homebrew (for Mac OSX):
```shell
brew install vagrant
```

Clone the project's repo and boot a build environment which can build:
```shell
git clone git@bldr-git.int.lineratesystems.com:velcro/PROJECTNAME.git
cd PROJECTNAME
vagrant up  # Downloads, boots, and provisions the box.
vagrant ssh  # Log into the fresh build system.
```

The project has already been cloned into the $GOPATH in the vagrant user's home
directory.


# Building
Use the 'gb' tools to build. Documentation for ```gb``` here:
[gb docs](http://getgb.io/)

```shell
cd PROJECTNAME
git submodule update --init  # This fetches all submodules, if any.
gb build  # This builds the project and puts the results in $GB_PROJECT_DIR/bin.
```

# Testing
Use the 'gb' tools to build. The 'gb' tooling does not yet provide code coverage, so simply use the ```scripts/coverage.sh``` to generate coverage data.

```shell
cd PROJECTNAME
gb test -v
scripts/coverage.sh
```

Don't forget to configure the new project for "Test coverage parsing". Simply go to the project's Settings page in GitLab and set "Test coverage parsing" to ```coverage:\s+(.*)\%\s+of\s+statements$```.


# Building a Debian package
Before building a Debian package (.deb) for the first time, some manual configuration is necessary. The files for configuring a Debian package reside in the ```debian``` subdirectory.


## Pre-build configuration
Before you build your first *deb*, you need to change the following files as appropriate for your project:
1. control.m4
  1. Update the *Source* line:
    1. Change ```go-project-template``` to the name of your project.
  2. Update the *Maintainer* line:
    1. Change ```YOURNAME``` to your Full name.
    2. Change ```YOUREMAIL``` to your e-mail address.
  3. Update the *Vcs-Git* URL as appropriate.
  4. Update the *Vcs-Browser* URL as appropriate.
  5. Update the *Package* line:
    1. Change ```go-project-template-bin``` to the name of your package.
  6. Update the *Provides* line:
    1. Change ```go-project-template-bin``` to the name of your package.
  7. Update the *Conflicts* line:
    1. Change ```go-project-template-bin``` to the name of your package.
  8. Update the *Description* line to provide a meaningful description for your package.
2. copyright
  1. Update the *Upstream-Name* line:
    1. Change ```go-project-template``` to the name of your project.
  2. Make sure the rest of the information is correct.
3. go-project-template-bin.install
  1. Rename to ```PACKAGENAME```.install.
  2. Make sure to map all project files to be included in the deb to their proper installation directories.
4. Generate your changelog file (NOTE: setting environment variables in your vagrant.d provisioning scripts will assure they are set in all your vagrant instances):
  1. Set ```DEBFULLNAME``` in your environment to your full name.
  2. Set ```DEBEMAIL``` in your environment to your e-mail address.
  3. Run this command to create the changelog file and add a meaningful description:
     ```shell
     dch --package PROJECTNAME --newversion 1.0.0
     ```
  4. At this point, the changelog file will reflect the version you specified as UNRELEASED, and any changes you make using the *dch* command will update this version. To mark the version as *released*, Run the following command:
  ```shell
  dch --release
  ```
  All subsequent *dch* commands will not affect *released* changelog versions.

## version.txt file
The version.txt file is located in the project directory and contains information required to build debian packages. The file contains variables and is sourced into bash scripts, so the variable declarations it contains must be valid bash syntax. The file currently contains two variables that must be correctly defined for your project:
1. *PROJECT_VERSION* - The current version of the project. It can contain any form of the product version as described in doc/versioning.md.
2. *VERSION_BRANCH* - Since most work in user workspaces is done in a branch other than master, this variable contains the name of the branch that the code will be merged to in the Velcro namespace. Currently it is set to 'master', but will change if/when we start feature development in feature branches. All version numbers identified by *PROJECT_VERSION* are specific to *VERSION_BRANCH*.

## Build your *deb*
From your project directory, run the following command to create a release package:
```shell
debian/package.sh -C debian <distro>
```
Where ```<distro>``` is the distro to build a package for, such as *wily*, *jessie*, etc. Other options include *--debug* to do a debug build or *--help*. The resulting package will end up in ~/*distro*

You can also use the Makefile to build packages for all supported distros by running:
```shell
make pkg-deb
```
or for a specific distro (in this case, wily):
```shell
make pkg-deb-wily
```

## Creating a releasable package
To create a releasable package you must first make sure the Debian changelog is up to date and the proper version tag is in git. The update-changelog.sh script was written for this purpose.

### Updating the Debian changelog
The update-changelog.sh script will show its usage when run with the *--help* option:
```shell
$ debian/update-changelog.sh --help
Usage: debian/update-changelog.sh [OPTIONS]

Update the Debian changelog. See the dch man page for more information.

OPTIONS:
    -h|--help           Show this help.
    -d|--debug          Script will emit copious debug output.
    -r|--dry-run        Do not actually update the changelog or commit to git.
    -l|--last-tag <tag> Use git commits since the specified tag or SHA.
```
The script can potentially make many changes to the changelog. To see what these changes are, run with the *--dry-run* option:
```shell
$ debian/update-changelog.sh --dry-run
```
Information for each commit will appear on the console to assist in identifying the actual changes being added. Running without the *--dry-run* option will generate an updated changelog. If the user wants to use it, it will replace the old one and committed to git, and the resulting commit will be tagged.

The script will automatically try to determine which commits should be used based on any previous version tags found. If no previous version tags are found then all commits are included, with the exception of merge commits as they are always excluded. Using the *--last-tag* option allows control over how much of the commit history will be included. The script will also ignore specific commits if its title matches a list of regular expressions built in for this purpose.

### Building the release package
To create a package based on the 1.0.1 version tag for Ubuntu wily, run the following command:
```shell
debian/package.sh -C debian -R v1.0.1 wily
```

# Code formatting and vetting
The Go language provides a source formatting tool and a sanitizer. Use it! When
in your project directory:

```shell
go fmt ./...
go vet ./...
```

These may become required to pass before merge requests are accepted in the
future.

# Vendoring velcro packages
Our internally developed packages are themselves complete gb-based projects
and include their own directory structure. This includes both ```src``` and ```vendor```
subdirectories.  To keep the import paths simple, these packages will be installed
under the top-level directory ```gb-pkgs```.  The top-level source directory of the 
installed velcro package will then be symbolicly linked under ```vendor/src/velcro```.

An example of adding the vlogger velcro package to PROJECTNAME is
shown below:

```shell
cd ~/PROJECTNAME
mkdir -p gb-pkgs
git submodule add git@bldr-git.int.lineratesystems.com:velcro/vlogger.git gb-pkgs/vlogger
mkdir -p vendor/src/velcro
cd vendor/src/velcro
ln -s ../../../gb-pkgs/vlogger/src/vlogger .
git add vlogger
```

Using the example above, the logger package can then be imported using the following
statement:

```go
import "velcro/vlogger"
```

# Vendoring 3rd party packages
All packages which are not part of velco repositories are considered "3rd party".
Follow the subsequent instructions for including 3rd party code. Note: do not
use ```go get```.


## Adding a vendor package
- Use the 'gb vendor' command to retrieve the vendor package and all of its dependencies.

```shell
cd ~/PROJECTNAME
gb vendor fetch bldr-git.int.lineratesystems.com/velcro/toyreverser.git
# fetching recursive dependency github.com/golang/example/stringutil
```

- Determine the licensing of each package. For all non-free licenses follow the instructions: https://docs.f5net.com/display/F5VELCROPROJ/Gitlab+Workflow#mirroring-for-nonfree-vendor-packages
- Fork all external packages into bldr-git/mirror.
  - In your browser, visit https://bldr-git.int.lineratesystems.com/groups/mirror
  - If the package you need is not there, it needs to be imported.
    1. Press the '+' in the upper right.
    1. Set the location to mirror/project (i.e. gb) and import using "URL from any repo" with the URL associated (i.e. https://github.com/golang/example) unless the name is something generic (i.e. github.com/golang/example), in which case it should be username-project (i.e. golang-example).
    1. In the project settings, add and enable the gitlab-ci "Deploy Key".
- Convert all of the packages fetched to git submodules. Remember that external packages that were imported into bldr-git/mirror need to reference the bldr-git repo, but the filesystem directory structure must be the external path. This is required so that import paths don't need to re-writing. Look at the ```submodule add``` command for "mirror/golang-example.git" as an example.

```shell
rm -rf vendor/src/bldr-git.int.lineratesystems.com/velcro/toyreverser
rm -rf vendor/src/github.com/golang/example
git submodule add git@bldr-git.int.lineratesystems.com:velcro/toyreverser.git vendor/src/bldr-git.int.lineratesystems.com/velcro/toyreverser
# Cloning into 'vendor/vendor/src/bldr-git.int.lineratesystems.com/velcro/toyreverser'...
# remote: Counting objects: 6, done.
# remote: Compressing objects: 100% (4/4), done.
# remote: Total 6 (delta 0), reused 0 (delta 0)
# Receiving objects: 100% (6/6), done.
# Checking connectivity... done.
git submodule add git@bldr-git.int.lineratesystems.com:mirror/golang-example.git vendor/src/github.com/golang/example
# Cloning into 'vendor/src/github.com/golang/example'...
# remote: Counting objects: 102, done.
# remote: Compressing objects: 100% (53/53), done.
# remote: Total 102 (delta 36), reused 102 (delta 36)
# Receiving objects: 100% (102/102), 74.12 KiB | 0 bytes/s, done.
# Resolving deltas: 100% (36/36), done.
# Checking connectivity... done.
```

## Updating a vendor package
Follow the directions for [updating a submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules#Cloning-a-Project-with-Submodules).
Basically:
```shell
git submodule update --remote vendor/src/.../<SUBMODULE_NAME>
```


## Changing branches
Submodules may exist in a branch and not in another branch. Be careful when switching branches to ensure you have the latest.
- Use ```git status``` to show the status of the working directory.
- Use ```git submodule update``` to update the registered submodules to match what the superproject expects

When something is missing, a build will show errors like the following.

```shell
gb build hello
# FATAL: command "build" failed: failed to resolve import path "hello": import "bldr-git.int.lineratesystems.com/velcro/toyreverser": not a directory
```

```shell
gb build
# FATAL: command "build" failed: no packages supplied
```

Fix these errors by either creating the new submodule (if you have imported a new package) or updating the submodule. The working directory has probably switched branches and needs to be completed. Use ```git submodule update``` to complete
the directory structure.


