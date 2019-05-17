// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

#![allow(unused)]
use log::warn;
use vm_device::dev::*;
use vm_device::device_manager::*;
use vm_device::system_allocate::*;
use vm_memory::mmap::GuestMemoryMmap;
use super::pci_bus::*;
use super::pci_device::*;
use super::pci_configuration::*;
use super::msix::*;
use super::msix::*;
use std::sync::{Arc, Mutex};

/// # Examples
/// * Dummy device initialization.
///
/// ```
/// # extern crate vm_device;
/// # extern crate vm_memory;
/// # use vm_memory::{GuestAddress, GuestMemoryMmap};
/// # use vm_device::system_allocate::*; // Need to be changed
/// # use vm_device::device_manager::*;
/// # use vm_pci::pci_bus::*;
/// # use vm_pci::pci_configuration::*;
/// # use vm_pci::dummy_device::*;
/// # let start_addr = GuestAddress(0x1000);
/// # let mut gm = GuestMemoryMmap::new(&vec![(start_addr, 0x800)]).unwrap();
/// # let mut sys_resource = SystemAllocator::new();
/// # let mut dev_mgr = DeviceManager::new(&mut sys_resource);
/// # let pci_bus = PciExBus::new("PciExpressBus".to_string(), BusType::PciExpressBus);
/// let dummy_dev = DummyPciDevice::new("DummyDevice".to_string());
/// //let mut bar0 = PciBarMSIx::new(0, 0x100, PciBarRegionType::Memory32BitRegion, PciBarPrefetchable::NotPrefetchable, gm);
/// ```

const DUMMY_MSIX_TABLE_OFFSET: u32 = 0;
const DUMMY_PBA_OFFSET: u32 = 0x1000;
const DUMMY_MSIX_VECTOR_NR: u32 = 2;

// Assume this dummy device has a msix bar.
pub struct PciBarMSIx {
    addr: u64,
    size: u64,
    reg_idx: usize,
    region_type: PciBarRegionType,
    prefetchable: PciBarPrefetchable,
    msix: MSIxStructure,
}

impl PciBarMSIx {
    pub fn new(
        reg_idx: usize,
        size: u64,
        region_type: PciBarRegionType,
        prefetchable: PciBarPrefetchable,
        memory: GuestMemoryMmap,
        msix_cap: usize
    ) -> Self {
        PciBarMSIx {
            addr: 0x100,
            size,
            reg_idx,
            region_type,
            prefetchable,
            // Dummy device has two msix vectors.
            msix: MSIxStructure::new(DUMMY_MSIX_VECTOR_NR as usize,
                                     memory, 0, 0, 0),
        }
    }

    pub fn msix_structure(&self) -> &MSIxStructure {
        &self.msix
    }

    pub fn msix_structure_mut(&mut self) -> &mut MSIxStructure {
        &mut self.msix
    }
}

impl PciBar for PciBarMSIx {
    fn set_address(&mut self, addr: Option<u64>) {
        if addr.is_some() {
            self.addr = addr.unwrap();
        } else {
            self.addr = 0;
        }
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn addr(&self) -> u64 {
        self.addr
    }

    fn reg_idx(&self) -> usize {
        self.reg_idx
    }

    fn region_type(&self) -> PciBarRegionType {
        self.region_type
    }

    fn prefetchable(&self) -> PciBarPrefetchable {
        self.prefetchable
    }

    // @offset: The offset from Bar address
    fn read_bar(&self, offset: u64, data: &mut [u8]) {
        let table_start = DUMMY_MSIX_TABLE_OFFSET;
        let table_end = table_start + DUMMY_MSIX_VECTOR_NR * 16; 
        let pba_start = DUMMY_PBA_OFFSET;
        let pba_end = pba_start + (DUMMY_MSIX_VECTOR_NR / 64) * 8;

        match offset as u32 {
            o if o >= table_start && o < table_end =>
                 self.msix_structure().msix_table_read((o - table_start) as usize, data),
            o if o >= pba_start && o < pba_end =>
                self.msix.msix_pba_read((0 - pba_start) as usize, data),
            _ => warn!("bad msix offset {}", offset)
        }
    }

    // @offset: The offset from Bar address
    fn write_bar(&mut self, offset: u64, data: &[u8]) {
        let table_start = DUMMY_MSIX_TABLE_OFFSET;
        let table_end = table_start + DUMMY_MSIX_VECTOR_NR * 16; 
        let pba_start = DUMMY_PBA_OFFSET;
        let pba_end = pba_start + (DUMMY_MSIX_VECTOR_NR / 64) * 8;

        // Software should never write PBA.
        match offset as u32 {
            o if o >= table_start && o < table_end =>
                 self.msix_structure_mut().msix_table_write((o - table_start) as usize, data),
            _ => warn!("bad msix offset {}", offset)
        }
    }
}

pub struct DummyPciDevice {
    name: String,
    config: PciConfiguration,
    bars: Vec<Arc<Mutex<dyn PciBar>>>,
}

impl DummyPciDevice {
    pub fn new(name: String) -> Self {
        DummyPciDevice {
            name: name,
            config: PciConfiguration::new(0,
                                          0,
                                          PciClassCode::Other,
                                          &PciMultimediaSubclass::Other,
                                          None,
                                          PciHeaderType::Device, 0, 0),
            bars: Vec::new(),
        }
    }

    fn get_resources(&mut self) -> Vec<ResReq> {
        let mut vec = Vec::new();
        for iter in self.bars.iter() {
            let size = iter.lock().expect("Failed to require lock").size();
            let addr = iter.lock().expect("Failed to require lock").addr();
            let region = iter.lock().expect("Failed to require lock").region_type();
            let res_type;

            match region {
                PciBarRegionType::IORegion => {res_type = IoType::Pio;}
                _ => {res_type = IoType::Mmio;}
            }
            match addr {
                x if x != 0 => {
                    vec.push(ResReq::new(Some(x), size, res_type, false));
                },
                _ => {
                    vec.push(ResReq::new(None, size, res_type, false));
                },
            }
        }
        vec
    }

    pub fn dummy_init(&mut self, gm: GuestMemoryMmap) {
        // let mut dummy_dev = DummyPciDevice::new("DummyDevice".to_string());
        // capability adding
        let msix_cap = MSIxCapablity::new(DUMMY_MSIX_VECTOR_NR as u16, DUMMY_MSIX_TABLE_OFFSET, 0, DUMMY_PBA_OFFSET, 0);
        if let Ok(offset) = self.config_registers_mut().add_capability(&msix_cap) {
            let mut bar0 = Arc::new(Mutex::new(PciBarMSIx::new(0,
                                               0x100,
                                               PciBarRegionType::Memory32BitRegion,
                                               PciBarPrefetchable::NotPrefetchable,
                                               gm, offset)));
            self.bars.push(bar0);
        } else {
            println!("Dummy device adding capability failed");
        }
    }
}

impl PciDevice for DummyPciDevice {
    /// Gets the configuration registers of the Pci Device.
    fn config_registers(&self) -> &PciConfiguration {
        &self.config
    }
    /// Gets the configuration registers of the Pci Device for modification.
    fn config_registers_mut(&mut self) -> &mut PciConfiguration {
        &mut self.config
    }
}

impl Device for DummyPciDevice {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn read(&self, addr: u64, data: &mut [u8], io_type: IoType) {
        // Find the Bar idx by @addr.
        let bar_idx = self.config.get_bar_idx_from_addr(addr);
        // Get the offset from the address specified by this Bar
        let offset = addr - self.bars[bar_idx].lock().expect("failed to require lock").addr();
        // Call Bar's read method.
        self.bars[bar_idx].lock().expect("failed to require lock").read_bar(offset, data);
    }

    fn write(&mut self, addr: u64, data: &[u8], io_type: IoType) {
        // Find the Bar idx by @addr.
        let bar_idx = self.config.get_bar_idx_from_addr(addr);
        // Get the offset from the address specified by this Bar
        let offset = addr - self.bars[bar_idx].lock().expect("failed to require lock").addr();
        self.bars[bar_idx].lock().expect("failed to require lock").write_bar(offset, data);
    }

    fn set_resources(&mut self, res: &[ResReq]) {
        for (idx, iter) in res.iter().enumerate() {
            self.bars[idx].lock().expect("Failed to require lock").set_address(iter.addr);
        }        
    }
}

#[cfg(test)]
mod tests {
    extern crate vm_device;
    extern crate vm_memory;

    use vm_memory::{GuestAddress, GuestMemoryMmap};
    use vm_device::system_allocate::*; // Need to be changed
    use vm_device::device_manager::*;
    use crate::pci_bus::*;
    use crate::pci_configuration::*;
    use crate::msix::*;
    use crate::dummy_device::*;
    #[test]
    fn vmm_init() {
        let start_addr = GuestAddress(0x1000);
        let mut gm = GuestMemoryMmap::new(&vec![(start_addr, 0x800)]).unwrap();
        let mut sys_res = SystemAllocator::new();
        let mut dev_mgr = DeviceManager::new(&mut sys_res);
        let pci_bus = PciExBus::new("PciExpressBus".to_string(), BusType::PciExpressBus);

        let mut dummy_dev = DummyPciDevice::new("DummyDevice".to_string());
        dummy_dev.dummy_init(gm.clone());

        // Get resource request.
        let mut res = dummy_dev.get_resources();
        // Register device into Device Manager.
        dev_mgr.register_device(Arc::new(Mutex::new(dummy_dev)), Some(Arc::new(Mutex::new(pci_bus))), &mut res);
    }

}
