F5 Container Service Connector for Kubernetes
=============================================

Introduction
------------

The F5® Container Service Connector (CSC) provides an integration for the `Kubernetes <http://kubernetes.io/>`_ orchestration environment that makes L4-L7 services available to users deploying miscroservices-based applications in a containerized infrastructure.

Releases and Compatibility
--------------------------

See the F5 Container Service Connector `Releases, Versioning, and Support Matrix <#>`_.

Documentation
-------------

Please refer to the `project documentation <docs/README.rst>`_ for configuration instructions.


For Developers
--------------

Project Setup
`````````````

Gitlab F5® CSC project:
git@bldr-git.int.lineratesystems.com:velcro/f5-k8s-controller.git

Vagrant environment
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    $ git clone git@bldr-git.int.lineratesystems.com:velcro/f5-k8s-controller.git
    $ cd f5-k8s-controller
    $ vagrant up
    $ vagrant ssh

Manual environment setup
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    $ sudo apt-get update
    $ sudo apt-get install devscripts equivs git golang golang-go.tools m4 \
        make python python-dev python-pip
    $ export GOPATH=$HOME/go
    $ mkdir $GOPATH
    $ export PATH=$PATH:$GOPATH/bin
    $ sudo go install -v -race runtime/race
    $ git clone https://bldr-git.int.lineratesystems.com/mirror/gb.git \
        $GOPATH/src/github.com/constabulary/gb
    $ git -C $GOPATH/src/github.com/constabulary/gb checkout 2b9e9134
    $ go install -v github.com/constabulary/gb/...
    $ git clone [gitlab F5® CSC project]
    $ cd f5-k8s-controller
    $ git submodule update --init --force
    # Install python requirements using sudo or create a virtualenv workspace.
    $ sudo pip install -r python/requirements.txt
    $ sudo pip install -r vendor/src/velcro/f5-marathon-lb/requirements.txt
    $ make release

Docker environment setup
~~~~~~~~~~~~~~~~~~~~~~~~

1. Install docker. For example, `Docker for Mac <https://docs.docker.com/engine/installation/mac/>`_
2. Build the docker images used for development (f5-k8s-ctrl-devel):
   ```make devel-image```
3. The ``run-in-docker.sh`` script can be used to run any command in a devel
   container, almost as if you ran it locally. For example, to run tests:
   ``./scripts/run-in-docker.sh make release``


Issues
------

To report an issue or suggest an enhancement, please open an `Issue <#>`_.

Configuration
-------------

See the `Project documentation <docs/README.rst>`_.


Copyright
---------

Copyright 2015-2016, F5 Networks Inc.

Support
-------

See `Support <SUPPORT.md>`_.

Contact
-------

coming soon!


License
-------
tbd

Contributor License Agreement
`````````````````````````````

Individuals or business entities who contribute to this project must have completed and submitted the `F5 Contributor License Agreement <#>`_ to <TBD>@f5.com prior to their code submission being included in this project.



