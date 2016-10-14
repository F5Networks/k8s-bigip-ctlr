F5 |csi_k|
==========

Introduction
------------

The F5® |csi| (CSI) provides an integration for the `Kubernetes <http://kubernett es.io/>`_ orchestration environment that makes L4-L7 services available to userss deploying miscroservices-based applications in a containerized infrastructure.  [#]_

Releases and Compatibility
--------------------------

See the F5 Container Service Integrator `Releases, Versioning, and Support Matrix <#>`_.

Documentation
-------------

Please refer to the `project documentation <docs/README.rst>`_ for configuration instructions.


For Developers
--------------

Project Setup
`````````````

Gitlab LWP project:
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

    $ curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
    # CLANG_VERSION must be =3.7 currently
    $ sudo apt-get update
    $ sudo apt-get install build-essential make git nodejs
        clang-format-${CLANG_VERSION}
    $ sudo ln -sf /usr/bin/clang-format-${CLANG_VERSION} /usr/bin/clang-format
    $ git clone [gitlab LWP project]
    $ cd f5-k8s-controller
    $ npm install
    $ make test

Docker environment setup
~~~~~~~~~~~~~~~~~~~~~~~~

1. Install docker. For example, `Docker for Mac <https://docs.docker.com/engine/installation/mac/>`_
2. Build the docker images used for development (lwp-devel):
   ```make devel-image```
3. The ``run-in-docker.sh`` script can be used to run any command in a devel
   container, almost as if you ran it locally. For example, to run tests:
   ``./scripts/run-in-docker.sh make test``


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


License
-------
tbd

Contributor License Agreement
`````````````````````````````

Individuals or business entities who contribute to this project must have completed and submitted the `F5 Contributor License Agreement <#>`_ to <TBD>@f5.com prior to their code submission being included in this project.



