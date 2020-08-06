# Real-Time Packet Capture and Filter

Sample config to simplify capture of a subset of STARDUST traffic.

These scripts use `corsarowdcap` from [Corsaro3](https://github.com/CAIDA/corsaro3) to attach to a STARDUST nDAG packet stream, filter based on a BPF, and the write captured packets to a pcap file that is periodically rotated.

## Usage

 1. Copy [corsarowdcap.filter-example.yaml](corsarowdcap.filter-example.yaml)
   - Replace the `inputfilter` parameter with the desired filter.
   - Ensure the correct interface name is specified in the `inputuri` parameter (see below). 
 2. Ensure output directory (default is `/home/limbo/pcap`) exists
 3. Run `corsarowdcap -c ./corsarowdap.myfilter.yaml` (replace `corsarowdcap.myfilter.yaml` with the name of your config file.

Note that you'll probably want to run corsarowdcap in screen (or tmux, etc.).

## `inputuri`

Depending on how your VM was built, you may need to replace the `ens3` portion of the `inputuri` field with the name of the interface that is on 10.224.0.0/16.

You can find this interface name by running:
```
ip a | grep 10.224 | awk '{print $(NF)}'
```
For example:
```
limbo@testing:~$ ip a | grep 10.224 | awk '{print $(NF)}'
ens3
```

