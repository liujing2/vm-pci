// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

#![allow(unused)]

use std::sync::Arc;
use super::pci_configuration::{PciConfiguration, PciCapability, PciCapabilityID};
use vm_memory::{ByteValued, Bytes, GuestAddress};
use vm_memory::mmap::GuestMemoryMmap;
use byteorder::{ByteOrder, LittleEndian};

use log::warn;

const MSIX_ENABLED_MASK: u32 = 0x0000_8000;
const MSIX_TABLE_SIZE_MASK: u16 = 0x03ff;
const MSIX_TABLE_BIR_MASK: u32 = 0x7;
const MSIX_TABLE_OFFSET: u32 = 3;
const MSIX_TABLE_OFFSET_MASK: u32 = 0xffff_fff8;
const MSIX_PBA_OFFSET: u32 = 3;
const MSIX_PBA_BIR_MASK: u32 = 0x7;
const MSIX_PBA_OFFSET_MASK: u32 = 0xffff_fff8;

const MSIX_ENTRY_SIZE: usize = 4;
const MSIX_ENTRY_VEC_CTRL_OFFSET: usize = 3;
const MSIX_ENTRY_VEC_CTRL_MASKBIT: u32 = 0x0000_0001;
const MSIX_ENTRY_UPP_ADDR_OFFSET: usize = 1;
const MSIX_ENTRY_DATA_OFFSET: usize = 2;


/// MSIx capability
#[derive(Clone, Copy, Default)]
pub struct MSIxCapablity {
    msg_ctl: u16,
    table_info: u32,
    pba_info: u32,
}

// It is safe to implement DataInit; all members are simple numbers and any value is valid.
unsafe impl ByteValued for MSIxCapablity {}

impl PciCapability for MSIxCapablity {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::MSIX
    }

    fn find(&self, id: PciCapabilityID) -> usize {
        0
    }
}

impl MSIxCapablity {
    pub fn new(nentries: u16, table_offset: u32, table_nr: u32,
               pba_offset: u32, pba_nr: u32) -> Self {
        MSIxCapablity {
            msg_ctl: (nentries - 1) & MSIX_TABLE_SIZE_MASK,
            table_info: (table_nr & MSIX_TABLE_BIR_MASK) | ((table_offset << MSIX_TABLE_OFFSET) & MSIX_TABLE_OFFSET_MASK),
            pba_info: (pba_nr & MSIX_PBA_BIR_MASK) | ((pba_offset << MSIX_PBA_OFFSET) & MSIX_PBA_OFFSET_MASK),
        }
    }
}


struct MSIxMessage {
    msg_addr: u64,
    msg_data: [u8; 4],
}

impl MSIxMessage {
    fn new(msg_addr: u64, data: u32) -> Self {
        let mut msg_data: [u8; 4] = [0; 4];
        let mut i = 0;
        for iter in msg_data.iter_mut() {
            *iter = *iter | (data >> (i * 8)) as u8;
            i = i + 1;
        }
        MSIxMessage {msg_addr, msg_data}
    }
}

/// A Device instance Bar would register all the included memory region
/// to DeviceManager. Take MSIx for example, Table Offset/Table BIR are
/// known by instance, and the corresponding Bar would register its region
/// with MSIx table range included.

/// Easily get MSIx information instead of reading config space every time.
///
/// Act as a common member of every Pci device instance.
pub struct MSIxStructure {
    // Guest memory mmap for getting host virtual address.
    memory: GuestMemoryMmap,
    // MSIx capability index in config space.
    msix_cap: usize,
    // MSIx table BIR.
    msix_table_bir: u32,
    // PBA BIR.
    pba_bir: u32,
    // Each msix table entry occupies 4 vector entries.
    msix_table: Vec<u32>,
    // Each entry describes 64 msix vectors.
    msix_pba: Vec<u64>,
}

impl MSIxStructure {
    pub fn set_msix_cap_offset(&mut self, offset: usize) {
        self.msix_cap = offset;
    }

    fn msix_table_size(&self, config: Arc<PciConfiguration>) -> u32 {
        let msg_ctl = (config.read_reg(self.msix_cap) >> 16) as u16;
        (msg_ctl & MSIX_TABLE_SIZE_MASK) as u32
    }

    /// MSIx table and PBA structure build.
    pub fn new(nentries: usize, memory: GuestMemoryMmap, msix_cap: usize, msix_table_bir: u32, pba_bir: u32) -> Self {
        // Build MSIx table.
        let mut msix_table: Vec<u32> = Vec::with_capacity(nentries * MSIX_ENTRY_SIZE);
        msix_table.resize(nentries * MSIX_ENTRY_SIZE, 0);

        // Init vector control mask bit
        for vector in 0..nentries {
            msix_table[vector * 4 + MSIX_ENTRY_VEC_CTRL_OFFSET] = MSIX_ENTRY_VEC_CTRL_MASKBIT;
        }

        // Build PBA structure
        let msix_pba = Vec::with_capacity((nentries + 64 - 1) / 64);

        MSIxStructure {
            memory,
            msix_cap,
            msix_table_bir,
            pba_bir,
            msix_table,
            msix_pba,
        }
    }

    /// MSIx enabled or not.
    pub fn msix_enabled(&self, config: Arc<PciConfiguration>) -> bool {
        if config.read_reg(self.msix_cap) >> 16 & MSIX_ENABLED_MASK == 0 {
            false
        } else {
            true
        }
    }

    /// Write MSIx table with offset and data.
    ///
    /// This would be called by the MSIx Bar method.
    /// @offset: the offset from msix table address within the BAR address.
    pub fn msix_table_write(&mut self, offset: usize, data: &[u8]) {
        let vector = offset / MSIX_ENTRY_SIZE;
        let was_masked = self.msix_is_masked(vector);

        // Check align
        if data.len() % 4 != 0  || offset % 4 != 0 {
            warn!("bad PCI MSIx table write command");
        }
        if let Some(r) = self.msix_table.get_mut(offset / (16 / MSIX_ENTRY_SIZE)) {
            *r = *r & LittleEndian::read_u32(data);
        } else {
            warn!("bad PCI MSIx table offset {}", offset);
        }
        // Check vector mask update and pending bit to do msix_notify
        self.msix_mask_update(vector, was_masked);
    }

    /// Read MSIx table with offset and data.
    ///
    /// This would be called by the MSIx Bar method.
    /// offset: the offset from msix_table.
    pub fn msix_table_read(&self, offset: usize, data: &mut [u8]) {
        // Check align
        if offset % 4 != 0 {
            warn!("bad PCI MSIx table write command");
        }

        LittleEndian::write_u32(data, self.msix_table[offset / (16 / MSIX_ENTRY_SIZE)]);
    }

    /// Read MSIx pba structure with offset and data.
    ///
    /// This would be called by the MSIx Bar method.
    /// offset: the offset from msix_pba.
    pub fn msix_pba_read(&self, offset: usize, data: &mut [u8]) {
        // Check align
        if offset % 4 != 0 {
            warn!("bad PCI MSIx table write command");
        }

        LittleEndian::write_u64(data, self.msix_pba[offset / 8 as usize]);
    }

    /// Software should never write PBA.
    //pub fn msix_pba_write(&self, offset: usize, data: &mut [u8]) {}

    fn msix_is_masked(&self, vector: usize) -> bool {
        let offset = vector * MSIX_ENTRY_SIZE;

        if self.msix_table[offset + MSIX_ENTRY_VEC_CTRL_OFFSET] & MSIX_ENTRY_VEC_CTRL_MASKBIT == 0 {
            return false;
        } else {
            return true;
        }
    }

    fn msix_has_pending(&self, vector: usize) -> bool {
        if self.msix_pba[vector / 64] & (1 << (vector % 64)) == 0 {
            return false;
        } else {
            return true;
        }
    }
    fn msix_clear_pending(&mut self, vector: usize) {
        let new = self.msix_pba[vector / 64] & !(1 << (vector % 64));

        self.msix_pba[vector / 64] = new;
    }

    fn msix_mask_update(&mut self, vector: usize, was_masked: bool) {
        let is_masked = self.msix_is_masked(vector);

        if is_masked == was_masked {
            return
        }

        if self.msix_has_pending(vector) {
            self.msix_clear_pending(vector);
            self.msix_notify(vector);
        }
    }

    fn msix_send_message(&self, msg: &MSIxMessage) {
        self.memory.write(&msg.msg_data, GuestAddress(msg.msg_addr));
    }

    fn msix_get_message(&self, vector: usize) -> MSIxMessage {
        let off = vector * MSIX_ENTRY_SIZE;
        let lo_addr = self.msix_table[off];
        let hi_addr = self.msix_table[off + MSIX_ENTRY_UPP_ADDR_OFFSET];
        let data = self.msix_table[off + MSIX_ENTRY_DATA_OFFSET];

        MSIxMessage::new((hi_addr as u64) << 32 | lo_addr as u64, data)
    }

    /// MSIx interrupt inject.
    pub fn msix_notify(&self, vector: usize) {
        // Get message from msix_table.
        let msg = self.msix_get_message(vector);
        // Send message.
        self.msix_send_message(&msg);
    }
}

