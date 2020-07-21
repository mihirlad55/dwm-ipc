# dwm-ipc
![Main CI](https://github.com/mihirlad55/dwm-ipc/workflows/Main%20CI/badge.svg)

dwm-ipc is a patch for dwm that implements inter-process communication through a
UNIX socket. This allows you to query the window manager for information, listen
for events such as tag changes or layout changes, as well as send commands to
control the window manager from other programs/scripts.


## Requirements
In order to build dwm you need the Xlib header files. The patch
additionally requires `yajl` which is a tiny C JSON library.


## Applying the Patch
The patch can be found on the
[Releases page](https://github.com/mihirlad55/dwm-ipc/releases). Download the
latest version of the patch that matches your version of dwm.

The patch is best applied after all of your other patches due to the number of
additions to dwm.c. The patch was designed with compatability in mind, so there
are minimal deletions.

### Tips
- Apply the patch last after all your other patches to avoid merge conflicts


## Patch Compatability
At the moment, the patch will only work on systems that implement epoll and is
not completely portable. Portability will be improved in the future.


## Supported IPC Messages
At the moment the IPC patch supports the following message requests:
- Run user-defined command (similar to key bindings)

- Get information about available layouts

- Get information about the tags available

- Get the properties of all of the monitors

- Get the properties of a specific dwm client

- Subscribe to tag change, client focus change, layout change events, monitor
focus change events, and focused title change events.

For more info on the IPC protocol implementation, visit the
[wiki](https://github.com/mihirlad55/dwm-ipc/wiki/).


## dwm-msg
`dwm-msg` is a cli program included in the patch which supports all of the IPC
message types listed above. The program can be used to run commands, query dwm
for information, and listen for events. This program is particularly useful for
creating custom shell scripts to control dwm.


## Related Projects
See [dwmipcpp](https://github.com/mihirlad55/dwmipcpp)

See [polybar dwm module \[WIP\]](https://github.com/mihirlad55/polybar)
