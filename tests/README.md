# Paper tests

This folder contains all the material related to the tests presented in the paper *Comparing User Space and In-Kernel Packet Processing for Edge Data Centers*.
A total of 14 tests is encompassed in the paper.
11 of them can be executed automatically through the python scripts available in this folder, while 3 of them have to be executed "by hand" due to the complex configuration.
The `res/` folders contain the raw results collected for automated tests in `.csv` format.

Two tests topologies are encompassed, based on the kinds of traffic that needs to be tested (namely dropped, pass-through and local).
Dropped and pass-through traffic consists in UDP packets and can by generated with MoonGen using the `gen-traffic.lua` script available in this folder.
Memcached is used to handle local traffic, that is generated with the [memoslap](https://github.com/FedeParola/memoslap) benchmarking tool.
Both testing topologies require and additional management connection since the interfaces used for test won't be available to process mgmt traffic.

The first testing topology is used when handling only one kind of traffic or when dropped and pass-through traffics are handled together.
It encompasses two machines (a DUT running the Network Function and `memcached` and a Tester generating the load) directly connected with a physical link.
```
+---+    +------+
|DUT|----|Tester|
+---+    +------+
```

The second topology, used only in the last test, encompasses a DUT and two Testers, one generating pass-through traffic and the other local traffic, all connected trough a switch.
```
+------+                +------------+
|Local |    +------+    |Pass-through|
|Tester|----|Switch|----|   Tester   |
+------+    +------+    +------------+
                |
              +---+
              |DUT|
              +---+
```

The `./scripts` folder contains scripts to configure the machines.
The following table describes the configuration of the flags to be provided to the XSKNF library to obtain the test modes described in the paper:

| Test mode   | Flags            | Notes |
|-------------|------------------|-------|
| XDP         | `-m XDP`         |       |
| AF_XDP      |                  |       |
| AF_XDP sysc | `-B`             | Run the scripts `{enable\|disable}_busy_poll <ifname>` to (un)configure  the interface |
| AF_XDP poll | `-p`             |       |
| XDP-sk      | `-m COMBINED -p` |       |
| XDP-sk sysc | `-m COMBINED -B` | Run the scripts `{enable\|disable}_busy_poll <ifname>` to (un)configure  the interface |

## Automated tests

Automated tests can be run through the Python scripts available in this folder.
Every script is named in the format `test-<traffic_kind>-<test_type>.py`, where:
- `<traffic_kind>` is one of `drop`, `passthrough`, `local` or `mixed` (dropped + pass-through traffic).
- `<test_type>` is one of:
  - `macswap`: to test *Pure I/O performance*.
  - `memory`: to test the *Impact of memory demand*.
  - `cpu`: to test the *Impact of CPU demand*.
  - Network function name: to test the *Traditional NF performance*. Three values are possible: `lb` (load balancer), `fw` (firewall) and `lbfw` (firewall chained with the load balancer).

This naming should make easy to map every script to the corresponding experiment in the paper.
A similar naming scheme applies to raw results in the `res/` folder (`res-<traffic_kind>-<test_type>.py`).

To run the automated tests:
1. Clone this repo on the *DUT* machine.
2. Build the library and examples running `make` into the root of the project.
3. Copy the `gen-traffic.lua` script on the *tester* machine.
4. Install and configure [MoonGen](https://github.com/emmericp/MoonGen) on the *tester* machine (please refer to the repo of the project for instructions).
5. Ensure the *DUT* can connect to the *tester* through passwordless SSH and can execute sudo command without password.
6. Edit the configuration constants of the desired script to reflect your setup (e.g., IP address of the *tester*, name of the interface to receive traffic).
7. On the *DUT*, run the script `setup_interface.sh <ifname>` with the name of the interface used for test to automatically configure it (the script enables the interface and puts it into promisc mode, set a single queue mapped on core 0 and configures DDIO ways).
7. Run the desired script.

### test-local-macswap

Before running the test please run the script `setup_local_afxdp_macswap.sh <ifname>` passing the name of the interface used for tests.
The script will create the configuration explained in the paper (based on a veth pair) to allow the AF_XDP program implementation of the NF to re-inject packets into the kernel.


## Manual tests

Before executing any test make sure the `setup_interface.sh <ifname>` has been run on the `DUT`.

### Local traffic pure I/O performance

The second sub-test for the *Pure I/O performance* scenario for local traffic requires the use of `memcached` to generate traffic crossing the TCP/IP stack.
This test leverages a total of 4 cores.

For the test modes processing traffic at the XDP level but excluding the *XDP-sk sysc* mode (namely, *XDP* and *XDP-sk*, details on the *XDP-sk sysc* mode can be found in the paper):
1. Configure the two interfaces of the *tester* and *DUT* with IP addresses on the same subnet (e.g. `172.0.0.1/24` and `172.0.0.2/24`).
2. Configure the interface on the *DUT* to receive traffic on 4 queues/cores with the script `set-rx-queues-rss.sh 4 <ifname>`.
3. Run `memcached` on the *DUT* on all 4 cores: `taskset f memcached -m 128 -t 4`.
4. Run the macswap example on the *DUT* with double macswap enabled, to prevent the Linux stack from discarding packets: `sudo ./macswap -i <ifname> {-M XDP | -M COMBINED -p} -- -d`.
5. (Optionally) enable or disable ATR (details in the paper): `sudo ethtool --set-priv-flags <ifname> flow-director-atr {on|off}`.
6. Run the `memoslap` benchmark on the *tester* (4 cores should be enough to saturate the *DUT*): `taskset f ./memoslap 172.0.0.1 11211 -t 4 -r 10`.

For the tests modes processing traffic at the AF_XDP level (namely, *AF_XDP*, *AF_XDP sysc* and *AF_XDP poll*):
1. Configure the networking on the *DUT* running the script `setup_local_afxdp_macswap.sh <ifname>`.
The script will create the configuration explained in the paper (based on a veth pair) and will instruct the NIC to send packets to the first queue/core.
2. Configure the `172.0.0.2/24` IP address on the *tester*.
3. Run the macswap example on the first core, with double macswap enabled: `taskset 1 sudo ./macswap -i <ifname> -i veth1b:c [-B] [-p] -- -d`.
4. Run `memcached` on the *DUT* on the 3 remaining cores: `taskset e memcached -m 128 -t 3`.
5. Run the `memoslap` benchmark on the *tester*.

For the *XDP-sk sysc* test mode:
1. Configure the two interfaces of the *tester* and *DUT* with IP addresses on the same subnet (e.g. `172.0.0.1/24` and `172.0.0.2/24`).
2. Configure the interface on the *DUT* to receive traffic on 1 queue/core running the script `set-rx-queues-rss.sh 1 <ifname>`.
3. Enable busy polling on the *DUT* with the script `enable_busy_poll.sh <ifname>`.
4. Run the macswap example on the first core, with double macswap enabled: `taskset 1 sudo ./macswap -i <ifname> -M COMBINED -B -- -d`.
5. Run `memcached` on the *DUT* on the 3 remaining cores: `taskset e memcached -m 128 -t 3`.
6. Run the `memoslap` benchmark on the *tester*.


### Local traffic traditional NF performance

For the *XDP* and *XDP-sk* test modes:
1. Configure the *DUT* running the script `setup_local_xdp_lb.sh <ifname> 4`, the script will generate a file `services.txt`.
2. Configure the *tester* with the script `setup_local_lb_client.sh <ifname>`.
3. Run `memcached` on the *DUT* on all 4 cores: `taskset f memcached -m 128 -t 4`.
4. Run the load balancer on the *DUT* with 512 pre-populated local sessions: `sudo ./load_balancer -i <ifname> {-M XDP|-M COMBINED -p} -- -l 512 -f <path_to_services.txt>`.
5. (Optionally) enable or disable ATR: `sudo ethtool --set-priv-flags <ifname> flow-director-atr {on|off}`.
6. Run the `memoslap` benchmark on the *tester* (pay attention to the `-p` flag): `taskset f ./memoslap 172.0.0.1 11211 -t 4 -r 10 -p`.

For the *AF_XDP*, *AF_XDP sysc* and *AF_XDP poll* tests modes:
1. Configure the *DUT* running the script `setup_local_afxdp_lb.sh <ifname> 1`.
2. Configure the *tester* with the script `setup_local_lb_client.sh <ifname>`.
3. Run the load balancer on the *DUT* with 512 pre-populated local sessions: `taskset 1 sudo ./load_balancer -i <ifname> -i veth1b:c [-B] [-p] -- -l 512 -f <path_to_services.txt>`.
4. Run `memcached` on the *DUT* on the 3 remaining cores: `taskset e memcached -m 128 -t 3`.
5. Run the `memoslap` benchmark on the *tester*.

For the *XDP-sk sysc* test mode:
1. Configure the *DUT* running the script `setup_local_xdp_lb.sh <ifname> 1`.
2. Configure the *tester* with the script `setup_local_lb_client.sh <ifname>`.
3. Enable busy polling on the *DUT* running the script `enable_busy_poll.sh <ifname>`.
4. Run the load balancer on the first core, with double macswap enabled: `taskset 1 sudo ./load_balancer -i <ifname> -M COMBINED -B -- -l 512 -f <path_to_services.txt>`.
3. Run `memcached` on the *DUT* on the 3 remaining cores: `taskset e memcached -m 128 -t 3`.
6. Run the `memoslap` benchmark on the *tester*.


### Mixing pass-through and local traffic

This test leverages the load balancer network function and requires a total of 4 cores.
With the hybrid solution (please refer to the paper for details) these cores can be partitioned between pass-through traffic, where the LB is executed in AF_XDP, or local traffic, where the LB is executed in XDP and each core is shared with a thread of `memcached`.
The test requires the second topology presented at the beginning of the the README.

To run the test with **N** cores allocated to pass-through traffic, and a total of **F** pass-through flows:
1. Configure the *DUT* running the script `setup_local_xdp_lb.sh <ifname> 4`, the script will generate a file `services.txt`.
2. Configure the *local tester* with the script `setup_local_lb_client.sh <ifname>`.
3. Setup the NIC of the *DUT* with script `setup_nic_hybrid.sh <ifname> 4 N`.
The scripts will create Ethernet Flow Director rules to steer pass-through flows on the first **N** queues and configure RSS to distribute all other flows on the remaining (4 - **N**) queues.
3. Enable busy polling on the *DUT* running the script `enable_busy_poll.sh <ifname>`.
4. Run the load balancer with **N** user space workers: `taskset -c 0-<N-1> sudo ./load_balancer -i <ifname> -M COMBINED -B -w <N> -- -p <F> -s -l 512 -f <path_to_services.txt>`.
5. Run `memcached` on the *DUT* on the remaining cores: `taskset -c <N>-3 memcached -m 128 -t <4-N>`.
6. Generate the desired amount of pass-through traffic on the *pass-through tester* with *MoonGen*: `sudo <path-to-moongen>/MoonGen <path-to-scripts>/gen-traffic.lua 0 0 -c 6 -r <desired-mbps> -f F -i <N>`
7. Run the `memoslap` benchmark on the *local tester*.