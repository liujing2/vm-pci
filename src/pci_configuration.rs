// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

#![allow(unused)]
// The number of 32bit registers in the config space, 256 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 64;

const NUM_BAR_REGS: usize = 6;

/// Contains the configuration space of a PCI node.
/// See the [specification](https://en.wikipedia.org/wiki/PCI_configuration_space).
/// The configuration space is accessed with DWORD reads and writes from the guest.
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    // writable bits for each register.
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS],
    bar_used: [bool; NUM_BAR_REGS],
    // Contains the byte offset and size of the last capability.
    last_capability: Option<(usize, usize)>,
}

