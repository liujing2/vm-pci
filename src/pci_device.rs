// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

#![allow(unused)]
use vm_device::dev::Device;
use super::pci_configuration::PciConfiguration;

const MSIX_ENABLED_MASK: u16 = 0x8000;
const MSIX_MSG_CTL_OFFSET: usize = 2;

// This trait will use pci_configuration::PciConfiguration but for clear design
// review and less dependency in example device realization, we temporarily use
// simple value for now.
pub trait PciDevice: Device {
    /// Gets the configuration registers of the Pci Device.
    fn config_registers(&self) -> &PciConfiguration;
    /// Gets the configuration registers of the Pci Device for modification.
    fn config_registers_mut(&mut self) -> &mut PciConfiguration;

    /// Read the configuration register according to register index.
    fn config_register_read(&self, _reg_idx: usize) -> u32; 

    /// Write the configuration register according to register index and offset.
    fn config_register_write(&mut self, reg_idx: usize, offset: u64, data: &[u8]);
}

