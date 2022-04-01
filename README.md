# XSKNF - Speed up development of AF_XDP-based NFs

The XSKNF library speeds up the development of AF_XDP based netowrk functions taking care of all aspects related to AF_XDP buffers and rings management and threading aspects.
The programmer just has to write a packet processing function that receives a single packet in input, processes it and provides a verdict.