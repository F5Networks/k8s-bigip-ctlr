# Package Versioning
Most/all of the code developed for the Velcro project will be distributed in some sort of binary package format. The first format that is supported is the Debian package format used by Ubuntu Linux. Support may be added for the RPM package format used by Redhat based distributions in the future; and also possibly the APK package format used by Alpine Linux. To reasonably support all of these platforms, a common package version string that works with all package systems is ideal as we would only have to set the version (using git tags) on a particular commit and it would apply to all packages built for that version. The version string should support different kinds of releases (alpha/beta/release-candidate/release) and should sort correctly such that alpha < beta < release-candidate < release for a given upstream version. In practice, this is possible with Debian and RPM packages by using a subset of characters in a specific format; but the same format does not work with APK packages, nor does there seem to be any easy way to make that happen. NOTE: I have not spent a significant amount of time researching APK package versions; but in any case we can always build tooling to transform the git version tags into something that works with APK versions. APK packages will not be discussed here any further until it is decided to support them.
## Version String Format
The format of the version string should be as follows to sort correctly in each package type:

**_projectName_-_upstreamVersion_** _[~alphaNumericString]_

The individual components are:
- Required:
  - projectName is the name of your project.
  - upstreamVersion is the current version of your project as 3 period-separated numbers major.minor.revision. This sorts in an obvious way.
- Optional:
  - ~alphaNumericString can be any combination of letters and numbers prefixed by a tilde. The way sorting works on this portion is not obvious, and requires further explanation:
    - The tilde is handled specially by both the Debian and RPM versioning schemes, and sorts before 'nothing' (projectName-1.0.0~ < projectName-1.0.0).
    - The rest of alphaNumericString is broken into groups - contiguous numbers are grouped together, contiguous letters are grouped together, and anything else forces a group break (12.34 is 2 groups of numbers and abcd.efgh is 2 groups of letters).
    - Each group is compared to its corresponding group in the version strings until a mismatch occurs (numbers are compared numerically, strings are compared as strings) or one version string runs out of groups in which is treated as an empty string.
    - The alphaNumericString should always start with a letter OR a number for a given upstreamVersion, as they are sorted differently for Debian (0 < A < a) and RPM (A < a < 0).
    - There are many other differences between the package version strings between package types, but we should not encounter them if the rules described in this section are followed.

### Examples (listed in ascending/newest sort order):
- First alpha for 1.0.0
  - projectName-1.0.0~alpha1
- Tenth alpha for 1.0.0
  - projectName-1.0.0~alpha10
- First beta for 1.0.0
  - projectName-1.0.0~beta1
- Tenth beta for 1.0.0
  - projectName-1.0.0~beta10
- First release candidate for 1.0.0
  - projectName-1.0.0~rc1
- Tenth release candidate for 1.0.0
  - projectName-1.0.0~rc10
- 1.0.0 Release
  - projectName-1.0.0
- 1.0.1 Release
  - projectName-1.0.1
- First alpha for 1.0.2
  - projectName-1.0.2~alpha1

## Verifying Package Version Strings
- On Ubuntu, the following commands can be run to compare package version strings:

``` shell
# Usage: dpkg --compare-versions <ver1> eq|lt|gt <ver2>
# Requires two version strings separated by a comparison operator; exits with 0 on success or 1 on failure

dpkg --compare-versions 1.0.0 eq 1.0.0
echo $?
0

dpkg --compare-versions 1.0.0 lt 1.0.0
echo $?
1

dpkg --compare-versions 1.0.0 gt 1.0.0
echo $?
1
```
- On a Redhat distro, the following command can be run to compare package version strings:

```shell
# Usage: rpmdev-vercmp <ver1> <ver2>
# Requires two version strings; prints a human-readable result to the console and exits with 0 if equal, 12 if ver1 < ver2, and 11 if ver1 > ver2.

rpmdev-vercmp 1.0.0 1.0.0
1.0.0 == 1.0.0
echo $?
0

rpmdev-vercmp 1.0.0 1.0.1
1.0.0 < 1.0.1
echo $?
12

rpmdev-vercmp 1.0.2 1.0.1
1.0.2 > 1.0.1
echo $?
11
```
- And for reference, here's the command to compare package version strings on Alpine Linux:

```shell
# Usage: apk version -t <ver1> <ver2>
# Requires two version strings; prints the appropriate comparison operator to the console. Always exits with 0.

apk version -t 1.0.0 1.0.0
=
echo $?
0

apk version -t 1.0.0 1.0.1
<
echo $?
0

apk version -t 1.0.2 1.0.1
>
echo $?
0
```
