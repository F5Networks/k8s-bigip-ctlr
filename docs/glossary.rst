:orphan: True

Glossary
========

.. glossary::
    :sorted:

    device
        `BIG-IP`_ hardware or virtual edition (VE).

    device service cluster
        Device Service Clustering provides synchronization and failover of `BIG-IP`_ configuration data among multiple `BIG-IP`_ devices on a network. You can configure a `BIG-IP`_ device on a network to synchronize some or all of its configuration data among several BIG-IP devices; fail over to one of many available devices; and/or mirror connections to a peer device to prevent interruption in service during failover.

    device group
       A device group is a component of a device service cluster. It consists of a collection of `BIG-IP`_ devices that trust each other and can synchronize, and sometimes fail over, their configuration data.

        partition
    partitions
        A BIG-IP partition, or *administrative partition*, is a user-acess-controlled container where a defined set of system objects can reside. Partitions allow admin users to to control other users’ access to BIG-IP objects. See `BIG-IP System User Account Administration -> Administrative Partitions`_ for more information.



.. _BIG-IP: https://f5.com/products/big-ip
.. _BIG-IP System: User Account Administration -> Administrative Partitions: https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-user-account-administration-12-0-0/3.html
