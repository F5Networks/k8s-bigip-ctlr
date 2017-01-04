f5-k8s-controller
=================


The F5 Container Connector (CC) for `Kubernetes <http://kubernetes.io/>`_ -- f5-k8s-controller -- makes F5 BIG-IP L4-L7 services available to microservices-based applications running in Kubernetes.

Releases and Compatibility
--------------------------

See the `Releases, Versioning, and Support Matrix <#blah.f5.com/support-matrix>`_.

Documentation
-------------

- `Project documentation <docs/README.rst>`_.
- User guides, demos, and more are available at `blah.f5.com <#>`_.

For Developers
--------------

Project Setup
`````````````

Gitlab F5 CC project:
git@bldr-git.int.lineratesystems.com:velcro/f5-k8s-controller.git

Vagrant environment
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    $ git clone [gitlab F5 CC project]
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
    $ git clone [gitlab F5 CC project]
    $ cd f5-k8s-controller
    $ git submodule update --init
    # Install python requirements using sudo or create a virtualenv workspace.
    $ sudo pip install -r python/requirements.txt
    $ sudo pip install -r vendor/src/velcro/f5-marathon-lb/requirements.txt
    $ make release

Docker environment setup
~~~~~~~~~~~~~~~~~~~~~~~~

Note: if setting up a new workspace run these commands first:

.. code-block:: bash

    $ git clone [gitlab F5 CC project]
    $ cd f5-k8s-controller
    $ git submodule update --init

1. Install docker. For example, `Docker for Mac <https://docs.docker.com/engine/installation/mac/>`_
2. Build the docker images used for development (f5-k8s-ctrl-devel):
   ```make devel-image```
3. The ``run-in-docker.sh`` script can be used to run any command in a devel
   container, almost as if you ran it locally. For example, to run tests:
   ``./scripts/run-in-docker.sh make release``

Running standalone
~~~~~~~~~~~~~~~~~~

Usually, the controller is deployed by Kubernetes. The example below shows how it can be run from the command-line. **This example is provided for enhanced understanding, not as a recommendation.**

   .. code-block:: shell

       docker run -it -d f5networks/lwp f5velcro/f5-k8s-controller --kubeconfig=./kubeconfig

   The controller will create a new application in your Kubernetes cluster to be the LWP for your application.



Issues
------

To report an issue or suggest an enhancement, please open an `Issue <https://bldr-git.int.lineratesystems.com/velcro/f5-k8s-controller/issues>`_.

Configuration
-------------

See `docs/README.rst`_.


Copyright
---------

Copyright 2015-2017, F5 Networks Inc.

Support
-------

See `Support <SUPPORT.md>`_.


License
-------
tbd

Contributor License Agreement
`````````````````````````````

Individuals or business entities who contribute to this project must have completed and submitted the `F5 Contributor License Agreement <#>`_ to <TBD>@f5.com prior to their code submission being included in this project.
