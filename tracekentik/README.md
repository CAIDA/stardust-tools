# tracekentik

Simple tool that uses libtrace to sample packets and send
them to the Kentik platform using protobuf.

Requirements
============

TODO:
To build tracekentik, you'll need the following libraries:
 * libtrace: https://research.wand.net.nz/software/libtrace.php
 * protobuf-c: https://github.com/protobuf-c/protobuf-c

Building
========

This should be easy, just run 'make' on the terminal within the
directory containing the tracekentik source code.


Running
=======

To stream the "Mini-NT" nDAG data:
```
tracekentik -s 1 -t 8 ndag:ens4,225.44.0.2,44000 127.0.0.1:8343
```

To stream the full telescope:
```
tracekentik -s 10 -t 8 ndag:ens4,225.44.0.1,44000 127.0.0.1:8343
```

To stream a file:
```
tracekentik -s 10 -t 0 pcapfile:/path/to/pcapfile 127.0.0.1:8343
```

You will also need kproxy running.
 - The kproxy for STARDUST integration is at https://github.com/kentik/darknet/
 - Run it like
 
 ```
 ./kproxy -api_email=ingest@kentik.com -log_level=info -host=0.0.0.0 -proxy_host=127.0.0.1 -port=8343 -healthcheck=127.0.0.1
 ```
