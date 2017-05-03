#!/bin/bash

set -e
set -x


# Checkout the source from submodules into go workspace
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
cd $GOPATH/src/github.com/F5Networks/k8s-bigip-ctlr

# Godep pulls in deps for all architectures, not just the current. Need to add
# extra deps because of this
# Whatever go-client wants
(cd $GOPATH/src/k8s.io/client-go && godep restore)
go get -d github.com/Sirupsen/logrus
go get -d golang.org/x/sys/unix
go get -d github.com/cihub/seelog

# Ensure previously pinned vendor versions haven't changed
while read d r s; do
  echo $d $r $s
  cd $GOPATH/src/
  cd $(dirname $d)
  cd $(basename $d)
  git checkout $s
done < vendors.txt
cd $GOPATH/src/github.com/F5Networks/k8s-bigip-ctlr

rm -rf Godeps 
rm -rf vendor
godep save ./...
git add vendor
git add Godeps
git commit -m 'Godep save

Checked out the exact verisons of previously deleted submodules, and saved deps
with godep

./godep-fixup/03-godep-save.sh
'
