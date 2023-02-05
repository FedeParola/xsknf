# XSKNF - Speed up development of AF_XDP-based NFs

The XSKNF library speeds up the development of AF_XDP based network functions taking care of all aspects related to AF_XDP buffers and rings management and threading aspects.
The programmer just has to write a packet processing function that receives a single packet in input, processes it and provides a verdict.

## Building

The library relies on **libbpf** and **libxdp** that are included as submodules and automatically updated when building.

The **libelf**, **libz**, and **libmnl** libraries are required and can be installed in Ubuntu with the following command:
```
sudo apt install libelf-dev zlib1g-dev libmnl-dev
```

Run `make` in the main project folder to build the library under [./src](./src) and the examples under [./examples](./examples).

## Application setup

To process packets in user space through AF_XDP sockets you just need to include the XSKNF library in yout program and implement the `xsknf_packet_processor()` function.
This function receives as parameters a pointer to the packet buffer, the length of the packet and the index of the ingress interface and must return the index of the output interface or `-1` to drop the packet.
Interface indexes reflect the order in which interfaces are passed on the command line (starting from `0`).

A typical application based on XSKNF can be called with a set of XSKNF-specific arguments, followed by a double hypen (`--`), followed by a set of application-specific arguments (in a similar way to how DPDK applications are invoked).
The following arguments are currently supported by the library:
```
-i, --iface=n[:m]   Interface to operate on (a copy mode between copy (c) or zero-copy (z)
                    can optionally be specified). Can be repeated multiple times
-p, --poll          Use poll syscall
-S, --xdp-skb=n     Use XDP skb-mode
-f, --frame-size=n  Set the frame size (must be a power of two in aligned mode, default is 4096)
-u, --unaligned     Enable unaligned chunk placement
-b, --batch-size=n  Batch size for sending or receiving packets. Default is 64
-B, --busy-poll     Busy poll
-M  --mode          Working mode (AF_XDP, XDP, COMBINED)
-w  --workers=n     Number of packet processing workers
```

The [macswap](./examples/macswap/) example provides a very basic example of how to use the library. For example it can be run in the follwing way:
```
sudo ./macswap -i ens1f0 -i ens1f1 -- -q
```
This command tells XSKNF to use interfaces `ens1f0` and `ens1f1` (`-i`) and the application not to print periodic statistics (`-q`).

## Architecture
TODO

## Paper

For the tests of the paper *Comparing User Space and In-Kernel Packet Processing for Edge Data Centers* please refer to the [tests](./tests) folder.