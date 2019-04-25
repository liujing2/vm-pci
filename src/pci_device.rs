// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

#![allow(unused)]
use vm_device::dev::Device;

// This trait will use pci_configuration::PciConfiguration but for clear design
// review and less dependency in example device realization, we temporarily use
// simple value for now.
pub trait PciDevice: Device {
    /// Read the configuration register according to register index.
    fn config_register_read(&self, _reg_idx: usize) -> u32; 

    /// Write the configuration register according to register index and offset.
    fn config_register_write(&mut self, reg_idx: usize, offset: u64, data: &[u8]);
}

