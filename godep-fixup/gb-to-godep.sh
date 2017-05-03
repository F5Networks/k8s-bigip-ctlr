#!/bin/bash

set -e
set -x


#git submodule status \
#  | awk '{print $2,$1}' \
#  | grep -v gb-pkgs \
#  | sed -e 's,^vendor/src/,,' \
#  | grep -v '^f5/' \
#  > vendors.txt


git submodule -q foreach sh -c 'd=$PWD && echo $d $(cd $d && git remote get-url origin) $(cd $d && git rev-parse HEAD)' \
  | sed -e "s,^$PWD/vendor/src/,," \
  | egrep -v "^(f5/|$PWD)" \
  > vendors.txt


# Checkout the source from submodules
while read d r s; do
  echo $d $r $s
  cd $GOPATH/src/
  mkdir -p $(dirname $d)
  cd $(dirname $d)
  rm -rf $(basename $d)
  git clone $r $(basename $d)
  cd $(basename $d)
  git checkout $s
done < vendors.txt

(cd $GOPATH/src/k8s.io/client-go && godep restore)

#go get -d github.com/Sirupsen/logrus
#go get -d golang.org/x/sys/unix
#go get -d github.com/cihub/seelog

while read d r s; do
  git rm -rf vendor/src/$d
done < vendors.txt


