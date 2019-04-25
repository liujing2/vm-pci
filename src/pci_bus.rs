// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause
#![allow(unused)]

use vm_device::dev::*;
use super::pci_device::*;
use byteorder::{ByteOrder, LittleEndian};
use std::sync::{Arc, Mutex};
use std::string::String;

/// PCI Bus
#[derive(Clone)]
pub struct PciBus {
    name: String,
    devices: Vec<Arc<Mutex<dyn PciDevice>>>,
    config_address_reg: u32,
}

impl PciBus {
    pub fn new(name: String, t: BusType) -> Self {
        PciBus {
            name: name,
            devices: Vec::new(),
            config_address_reg: 0,
        }
    }

    pub fn insert(&mut self, dev: Arc<Mutex<dyn PciDevice>>) {
        self.devices.push(dev);
    }

    fn get_resource_request(&self) -> Vec<ResReq> {
        let mut req_vec = Vec::new();

        let res = ResReq::new(Some(0xcf8), 8, IoType::Pio, false),
        req_vec.push(res);
        req_vec
    }

    fn parse_config_address(&self, config_address: u32, t: BusType) -> (usize, usize, usize, usize) {
        let mut bus_number_offset: usize = 16;
        let mut bus_number_mask: u32 = 0x00ff;
        let mut device_number_offset: usize = 11;
        let mut device_number_mask: u32 = 0x1f;
        let mut function_number_offset: usize = 8;
        let mut function_number_mask: u32 = 0x07;
        let mut register_number_offset: usize = 2;
        let mut register_number_mask: u32 = 0x3f;

        let bus_number = ((config_address >> bus_number_offset) & bus_number_mask) as usize;
        let device_number =
            ((config_address >> device_number_offset) & device_number_mask) as usize;
        let function_number =
            ((config_address >> function_number_offset) & function_number_mask) as usize;
        let register_number =
            ((config_address >> register_number_offset) & register_number_mask) as usize;

        (bus_number, device_number, function_number, register_number)
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                (data[0] as u32) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 16),
                ((data[1] as u32) << 8 | data[0] as u32) << (offset * 16),
            ),
            4 => (0xffff_ffff, LittleEndian::read_u32(data)),
            _ => return,
        };
        self.config_address_reg = (self.config_address_reg & !mask) | value;
    }
}

impl Device for PciBus {
    fn read(&self, addr: u64, data: &mut [u8], io_type: IoType) {
        let value: u32 = match addr {
            // Legacy PCI configuration space
            0xcf8...0xcfb => self.config_address_reg,
            0xcfc...0xcff => {
                let (_bus, device, _function, register) =
                    self.parse_config_address(self.config_address_reg & !0x8000_0000, self.bus_type);
                self.devices.get(device - 1).map_or(0xffff_ffff, |d| {
                    d.lock()
                     .expect("failed to acquire lock")
                     .config_register_read(register)
                })
            },
        },
        // Only allow reads to the register boundary.
        let start = (addr - 0xcf8) as usize % 4;
        let end = start + data.len();
        if end <= 4 {
            for i in start..end {
                data[i - start] = (value >> (i * 8)) as u8;
            }
        } else {
            for d in data {
                *d = 0xff;
            }
        }
            
    }

    fn write(&mut self, addr: u64, data: &[u8], io_type: IoType) {
        match addr {
            0xcf8...0xcfb => {
                self.set_config_address(addr - 0xcf8, data);
            }
            0xcfc...0xcff => {
                let enabled = (self.config_address_reg & 0x8000_0000) != 0;
                if !enabled {
                    return;
                }
                let (_bus, device, _function, register) =
                    self.parse_config_address(self.config_address_reg & !0x8000_0000, self.bus_type);
                if let Some(d) = self.devices.get(device - 1) {
                    d.lock()
                        .expect("failed to acquire lock")
                        .config_register_write(register, addr - 0xcfc, data);
                }
            }
        }
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn set_resources(&mut self, res: &[ResReq]) {
        // Do nothing for legacy PCI.
    }
}
