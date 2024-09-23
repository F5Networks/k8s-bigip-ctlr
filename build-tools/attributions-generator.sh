#!/bin/bash

#
# Run the arrtibutions generator container
#

#set -e
#set -x

generate_attributions_licensee() {

  vendor="$1"
  repos=`ls $vendor`

  for repo in $repos; 
    do for projects in `ls $vendor/$repo`; 
      # If repo is github.com or golang.org, we need to perform an extra iteration.
      do 
        if [ $repo == "modules.txt" ]
        then	
          echo "Cannot handle this repo: $repo"
          continue
        fi	
        if [ $repo == "github.com" ]  || [ $repo == "golang.org" ]
        then
        for package in `ls $vendor/$repo/$projects`;
          do echo $repo/$projects/$package;   
            # Licensee is not able to detect the package mergo license.
            # Need to raise an issue with mergo
            if [ $package == mergo ]
            then
              echo "Unable to detect the license type"
              continue
            fi
            # Licensee is not able to detect the license file path.
            # Need to raise an issue with licensee.
            if [ $projects == "xeipuuv" ] || [ $projects == "hpcloud" ]
            then
              license_text="License:        Apache-2.0
Matched files:  LICENSE-APACHE-2.0.txt
LICENSE-APACHE-2.0.txt:
  Content hash:  ab3901051663cb8ee5dea9ebdff406ad136910e3
  Confidence:    100.00%
  Matcher:       Licensee::Matchers::Exact
  License:       Apache-2.0"
            echo "$license_text"
            head -25 $vendor/$repo/$projects/$package/LICENSE-APACHE-2.0.txt
            continue
            fi
            if [ $projects == "cespare" ]  && [ $package == "xxhash" ]
            then
              package=$package/v2
              licensee detect $vendor/$repo/$projects/$package
              head -25 $vendor/$repo/$projects/$package/LICENSE.txt
              continue
            fi
            if [ $projects == "f5devcentral" ] && [ $package == "go-bigip" ]; then
                package=$package/f5teem
            fi
            if [ $projects == "emicklei" ] && [ $package == "go-restful" ]; then
              package=$package/v3
            fi
            licensee detect $vendor/$repo/$projects/$package
            licensee license-path $vendor/$repo/$projects/$package | xargs head -25
            echo
        done ; 
        else 
        echo $repo/$projects ;
        if [ $repo == "k8s.io" ]  && [ $projects == "klog" ]
        then
          projects=$projects/v2
        fi
        if [ $repo == "sigs.k8s.io" ]  && [ $projects == "structured-merge-diff" ]
        then
          projects=$projects/v4
        fi
        licensee detect $vendor/$repo/$projects;
        licensee license-path $vendor/$repo/$projects | xargs head -25
        echo
        fi
    done ;
  done

}

generate_attributions_licensee $1 > /opt/all_attributions.txt