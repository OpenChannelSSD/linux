# LightNVM: A host-side driver for Open-Channel Solid State Drives

Open-channel SSDs are devices which exposes direct access to its physical
flash storage, while keeping a subset of the internal features of SSDs.

A common SSD consists of a flash translation layer (FTL), bad block
management, and hardware units such as flash and host
interface controllers and couple it with a large amount of flash chips.

Open-Channel SSDs moves part of the FTL responsibility into the host, allowing
the host to manage data placement, garbage collection and parallelism. The
device continues to maintain information such as bad block management, implements
a simpler FTL, which allows extensions such as atomic IOs, metadata
persistence and similar to be implemented.

The architecture of LightNVM consists of a core and multiple targets. The core
implements functionality shared across targets, such as initialization, teardown
and statistics. The targets are how physical flash are
exposed to user-space. This can be as a block device, key-value store,
object-store, etc.

LightNVM is currently hooked up through the null_blk and NVMe driver. The NVMe
extension allow development using the LightNVM-extended QEMU implementation,
using Keith Busch's qemu-nvme branch.

# How to use
-------------

To use LightNVM, a device is required to register as an open-channel SSD.

Currently, two implementations exist. The null_blk and NVMe driver. The
null_blk driver is for performance testing, while the NVMe driver can be
initialized using a patches version of Keith Busch's QEMU NVMe simulator, or if
real hardware is available.

The QEMU branch is available at:

    https://github.com/OpenChannelSSD/qemu-nvme

Follow the guide at

    https://github.com/OpenChannelSSD/linux/wiki

# Available Hardware

A couple of open platforms are currently being ported to utilize LightNVM:

 IIT Madras (https://bitbucket.org/casl/ssd-controller)
   An open-source implementation of a NVMe controller in BlueSpec. Can run on
   Xilix FPGA's, such as Artix 7, Kintex 7 and Vertex 7.

 MemBlaze eBlaze (https://github.com/OpenChannelSSD/memblaze-eblaze)
   A high-performance SSD that exposes direct flash to the host. The device driver is in progress. 

 OpenSSD Jasmine (http://www.openssd-project.org/)
   An open-firmware SSD, that allows the user to implement its own FTL within
   the controller.

   An experimental patch of the firmware is found in the lightnvm branch:
     https://github.com/ClydeProjects/OpenSSD/

   Todo: Requires bad block management to be useful and storing of host FTL
   metadata.

 OpenSSD Cosmos (http://www.openssd-project.org/wiki/Cosmos_OpenSSD_Platform)
   A complete development board with FPGA, ARM Cortex A9 and FPGA-accelerated
   host access.

# Draft Specification

We are currently creating a draft specification as more and more of the
host/device interface is stabilized. Please see this Google document. It's open
for comments.

  http://goo.gl/BYTjLI

In the making
-------------

 * Bad block management. This is kept device side, however the host still
   requires bad block information to prevent writing to dead flash blocks.
 * Space-efficient algorithms for translation tables.



