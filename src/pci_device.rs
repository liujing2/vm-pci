// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

#![allow(unused)]
use vm_device::dev::Device;
use super::pci_configuration::*;
use byteorder::{ByteOrder, LittleEndian};

// review and less dependency in example device realization, we temporarily use
// simple value for now.
pub trait PciDevice: Device {
    /// Gets the configuration registers of the Pci Device.
    fn config_registers(&self) -> &PciConfiguration;
    /// Gets the configuration registers of the Pci Device for modification.
    fn config_registers_mut(&mut self) -> &mut PciConfiguration;

    /// Read the configuration register according to register index.
    fn config_register_read(&self, reg_idx: usize) -> u32 {
        self.config_registers().read_reg(reg_idx)
    }

    /// Write the configuration register according to register index and offset.
    fn config_register_write(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }

        let regs = self.config_registers_mut();

        match data.len() {
            1 => regs.write_byte(reg_idx * 4 + offset as usize, data[0]),
            2 => regs.write_word(
                reg_idx * 4 + offset as usize,
                (data[0] as u16) | (data[1] as u16) << 8,
            ),
            4 => regs.write_reg(reg_idx, LittleEndian::read_u32(data)),
            _ => (),
        }
    }
}

