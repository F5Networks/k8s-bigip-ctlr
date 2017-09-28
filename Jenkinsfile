#!/usr/bin/env groovy

pipeline {
  agent {
    label "rhel7"
  }
  options {
        ansiColor('xterm')
        timestamps()
        timeout(time: 150, unit: "MINUTES")
  }
  stages {
    stage("build") {
      steps {
        sh '''#!/usr/bin/env bash
          export BASE_OS=rhel7
          export GIT_COMMIT=$(git rev-parse HEAD)
          export GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
          DOCKER_NAMESPACE="docker-registry.pdbld.f5net.com/velcro"
          BASE_PUSH_TARGET="$DOCKER_NAMESPACE/k8s-bigip-ctlr"
          export IMG_TAG="${BASE_PUSH_TARGET}:${GIT_COMMIT}-$BASE_OS"
          export BUILD_IMG_TAG="${BASE_PUSH_TARGET}-devel:${GIT_COMMIT}-$BASE_OS"
          export CLEAN_BUILD=true
          build-tools/build-devel-image.sh
          build-tools/build-debug-artifacts.sh
          build-tools/build-release-artifacts.sh
          build-tools/build-release-images.sh
          docker tag "$IMG_TAG" "$BASE_PUSH_TARGET:devel-$GIT_BRANCH-$BASE_OS"
          docker tag "$IMG_TAG" "$BASE_PUSH_TARGET:devel-$GIT_BRANCH-n-$BUILD_NUMBER-id-$BUILD_ID-$BASE_OS"
          docker push "$IMG_TAG"
          docker push "$BASE_PUSH_TARGET:devel-$GIT_BRANCH-$BASE_OS"
          docker push "$BASE_PUSH_TARGET:devel-$GIT_BRANCH-n-$BUILD_NUMBER-id-$BUILD_ID-$BASE_OS"
        '''
      }
    }
  }
  post {
    always {
      // cleanup workspace
      dir("${env.WORKSPACE}") { deleteDir() }
    }
  }
}
