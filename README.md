# Wireshark dissector for the Keyence LJ-V (7000) Ultra-High Speed In-Line Profilometer ethernet protocol
v0.1.1


## Overview

This repository contains a Lua Wireshark dissector for the Keyence LJ-V (7000)
Ultra-High Speed In-Line Profilometer ethernet protocol. This protocol is
used by the [Keyence LJ-V7000][] profilometer series of products.

The dissector was used to help implement a custom interface to the Keyence
sensor and dissects only those message structures that were needed for that
interface.

Note: only traffic on the 'TCP command port' (default: 24691) is currently
dissected. Support for the 'TCP high-speed port' will be added in a later
revision.

Note 2: packet / command names are only loosely based on the available
documentation and have been adapted sometimes to better fit available UI
space.

Documentation used:

 1. Keyence LJ-V7000 Series Communication Library, Reference Manual,
    LJ-V7000_COM_RM_E, 376GB, 2nd rev, 2nd ed., August 2014
 1. Keyence LJ-V7000 Series protocol documentation (not publicly available)


## Installation

### Linux

Copy or symlink the `packet-keyence-lj-v7000.lua` file to either the Wireshark
global (`/usr/(local/)share/wireshark/plugins`) or per-user
(`$HOME/.wireshark/plugins`) plugin directory.

### Windows

Copy the the `packet-keyence-lj-v7000.lua` file to either the Wireshark
global (`%WIRESHARK%\plugins`) or per-user (`%APPDATA%\Wireshark\plugins`)
plugin directory.


## Compatible Wireshark versions

The dissector has been extensively used with Wireshark versions 1.11.x and
1.12.x, but is expected to work on most versions with Lua support.


## Configuration

The dissector currently has one configurable option:

 1. Include fixed fields: should fields documented as "Don't Care", "Ignore"
    and "Fixed" be included in the Packet Details? This will add items for
    those fields to the tree.



[Keyence LJ-V7000]: http://www.keyence.com/products/measure/laser-2d/lj-v/index.jsp
