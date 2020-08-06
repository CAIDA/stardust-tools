# Real-Time Packet Capture and Filter

Sample config to simplify capture of a subset of STARDUST traffic.

These scripts use `corsarowdcap` from [Corsaro3](https://github.com/CAIDA/corsaro3) to attach to a STARDUST nDAG packet stream, filter based on a BPF, and the write captured packets to a pcap file that is periodically rotated.

## Usage

 1. Copy [corsarowdcap.filter-example.yaml](corsarowdcap.filter-example.yaml) and replace (at least) the `inputfilter`parameter.
 2. Ensure output directory (default is `/home/limbo/pcap`) exists
 3. Run `corsarowdcap -c ./corsarowdap.myfilter.yaml` (replace `corsarowdcap.myfilter.yaml` with the name of your config file.

Note that you'll probably want to run corsarowdcap in screen (or tmux, etc.).

