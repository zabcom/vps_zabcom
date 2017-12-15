#qemu-system-x86_64 -hda ./disk-qemu.qcow2 -m 4096 -curses -s
qemu-system-x86_64 -hda ./disk-qemu.qcow2 -m 4096 -nographic -s -monitor telnet:127.0.0.1:1237,server,nowait  -curses
