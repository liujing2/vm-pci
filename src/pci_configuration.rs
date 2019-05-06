// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

#![allow(unused)]

// TODO: Use sys_util::warn instead
use log::warn;

use std::fmt::{self, Display};

// The number of 32bit registers in the config space, 256 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 1024;

const STATUS_REG: usize = 1;
const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
const BAR0_REG: usize = 4;
const BAR_IO_ADDR_MASK: u32 = 0xffff_fffc;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const BAR_MEM_REGION_WIDTH_MASK: u32 = 0x0000_0ff0;
const NUM_BAR_REGS: usize = 6;
const CAPABILITY_LIST_HEAD_OFFSET: usize = 0x34;
const FIRST_CAPABILITY_OFFSET: usize = 0x40;
const CAPABILITY_MAX_OFFSET: usize = 192;

const PCI_BAR_ADDRESS_START: usize = 0x10;
const PCI_BAR_ADDRESS_END: usize = 0x16;


/// Represents the types of PCI headers allowed in the configuration registers.
#[derive(Copy, Clone)]
pub enum PciHeaderType {
    Device,
    Bridge,
}

/// Classes of PCI nodes.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciClassCode {
    TooOld,
    MassStorage,
    NetworkController,
    DisplayController,
    MultimediaController,
    MemoryController,
    BridgeDevice,
    SimpleCommunicationController,
    BaseSystemPeripheral,
    InputDevice,
    DockingStation,
    Processor,
    SerialBusController,
    WirelessController,
    IntelligentIoController,
    EncryptionController,
    DataAcquisitionSignalProcessing,
    Other = 0xff,
}

impl PciClassCode {
    pub fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// A PCI sublcass. Each class in `PciClassCode` can specify a unique set of subclasses. This trait
/// is implemented by each subclass. It allows use of a trait object to generate configurations.
pub trait PciSubclass {
    /// Convert this subclass to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Subclasses of the MultimediaController class.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciMultimediaSubclass {
    VideoController = 0x00,
    AudioController = 0x01,
    TelephonyDevice = 0x02,
    AudioDevice = 0x03,
    Other = 0x80,
}

impl PciSubclass for PciMultimediaSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclass of the SerialBus
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciSerialBusSubClass {
    Firewire = 0x00,
    ACCESSbus = 0x01,
    SSA = 0x02,
    USB = 0x03,
}

impl PciSubclass for PciSerialBusSubClass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// A PCI class programming interface. Each combination of `PciClassCode` and
/// `PciSubclass` can specify a set of register-level programming interfaces.
/// This trait is implemented by each programming interface.
/// It allows use of a trait object to generate configurations.
pub trait PciProgrammingInterface {
    /// Convert this programming interface to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Types of PCI capabilities.
pub enum PciCapabilityID {
    ListID = 0,
    PowerManagement = 0x01,
    AcceleratedGraphicsPort = 0x02,
    VitalProductData = 0x03,
    SlotIdentification = 0x04,
    MessageSignalledInterrupts = 0x05,
    CompactPCIHotSwap = 0x06,
    PCIX = 0x07,
    HyperTransport = 0x08,
    VendorSpecific = 0x09,
    Debugport = 0x0A,
    CompactPCICentralResourceControl = 0x0B,
    PCIStandardHotPlugController = 0x0C,
    BridgeSubsystemVendorDeviceID = 0x0D,
    AGPTargetPCIPCIbridge = 0x0E,
    SecureDevice = 0x0F,
    PCIExpress = 0x10,
    MSIX = 0x11,
    SATADataIndexConf = 0x12,
    PCIAdvancedFeatures = 0x13,
    PCIEnhancedAllocation = 0x14,
}

/// A PCI capability list.
///
/// Devices can optionally specify capabilities in their configuration space.
pub trait PciCapability {
    /// Get capability length.
    fn bytes(&self) -> &[u8];
    /// Get capability ID.
    fn id(&self) -> PciCapabilityID;
    /// Find capability addr by ID.
    fn find(&self, id: PciCapabilityID) -> usize;
}

#[derive(Debug)]
pub enum Error {
    BarAddressInvalid(u64, u64),
    BarInUse(usize),
    BarInUse64(usize),
    BarInvalid(usize),
    BarInvalid64(usize),
    BarSizeInvalid(u64),
    CapabilityEmpty,
    CapabilityLengthInvalid(usize),
    CapabilitySpaceFull(usize),
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            BarAddressInvalid(a, s) => write!(f, "address {} size {} too big", a, s),
            BarInUse(b) => write!(f, "bar {} already used", b),
            BarInUse64(b) => write!(f, "64bit bar {} already used(requires two regs)", b),
            BarInvalid(b) => write!(f, "bar {} invalid, max {}", b, NUM_BAR_REGS - 1),
            BarInvalid64(b) => write!(
                f,
                "64bitbar {} invalid, requires two regs, max {}",
                b,
                NUM_BAR_REGS - 1
            ),
            BarSizeInvalid(s) => write!(f, "bar address {} not a power of two", s),
            CapabilityEmpty => write!(f, "empty capabilities are invalid"),
            CapabilityLengthInvalid(l) => write!(f, "Invalid capability length {}", l),
            CapabilitySpaceFull(s) => write!(f, "capability of size {} doesn't fit", s),
        }
    }
}

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

impl PciConfiguration  {
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        class_code: PciClassCode,
        subclass: &dyn PciSubclass,
        programming_interface: Option<&dyn PciProgrammingInterface>,
        header_type: PciHeaderType,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];
        registers[0] = u32::from(device_id) << 16 | u32::from(vendor_id);
        // TODO(dverkamp): Status should be write-1-to-clear
        writable_bits[1] = 0x0000_ffff; // Status (r/o), command (r/w)
        let pi = if let Some(pi) = programming_interface {
            pi.get_register_value()
        } else {
            0
        };
        registers[2] = u32::from(class_code.get_register_value()) << 24
            | u32::from(subclass.get_register_value()) << 16
            | u32::from(pi) << 8;
        writable_bits[3] = 0x0000_00ff; // Cacheline size (r/w)
        match header_type {
            PciHeaderType::Device => {
                registers[3] = 0x0000_0000; // Header type 0 (device)
                writable_bits[15] = 0x0000_00ff; // Interrupt line (r/w)
            }
            PciHeaderType::Bridge => {
                registers[3] = 0x0001_0000; // Header type 1 (bridge)
                writable_bits[9] = 0xfff0_fff0; // Memory base and limit
                writable_bits[15] = 0xffff_00ff; // Bridge control (r/w), interrupt line (r/w)
            }
        };
        registers[11] = u32::from(subsystem_id) << 16 | u32::from(subsystem_vendor_id);

        PciConfiguration {
            registers,
            writable_bits,
            bar_used: [false; NUM_BAR_REGS],
            last_capability: None,
        }
    }

    /// Reads a 32bit register from `reg_idx` in the register map.
    pub fn read_reg(&self, reg_idx: usize) -> u32 {
        *(self.registers.get(reg_idx).unwrap_or(&0xffff_ffff))
    }

    /// Writes a 32bit register to `reg_idx` in the register map.
    pub fn write_reg(&mut self, reg_idx: usize, value: u32) {
        if let Some(r) = self.registers.get_mut(reg_idx) {
            *r = value & self.writable_bits[reg_idx];
        } else {
            warn!("bad PCI register write {}", reg_idx);
        }
    }

    /// Writes a 16bit word to `offset`. `offset` must be 16bit aligned.
    pub fn write_word(&mut self, offset: usize, value: u16) {
        let shift = match offset % 4 {
            0 => 0,
            2 => 16,
            _ => {
                warn!("bad PCI config write offset {}", offset);
                return;
            }
        };
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = self.writable_bits[reg_idx];
            let mask = (0xffffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Writes a byte to `offset`.
    pub fn write_byte(&mut self, offset: usize, value: u8) {
        self.write_byte_internal(offset, value, true);
    }

    /// Writes a byte to `offset`, optionally enforcing read-only bits.
    fn write_byte_internal(&mut self, offset: usize, value: u8, apply_writable_mask: bool) {
        let shift = (offset % 4) * 8;
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = if apply_writable_mask {
                self.writable_bits[reg_idx]
            } else {
                0xffff_ffff
            };
            let mask = (0xffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Adds the capability `cap_data` to the list of capabilities.
    /// `cap_data` should include the two-byte PCI capability header (type, next),
    /// but not populate it. Correct values will be generated automatically based
    /// on `cap_data.id()`.
    pub fn add_capability(&mut self, cap_data: &dyn PciCapability) -> Result<usize> {
        let total_len = cap_data.bytes().len();
        // Check that the length is valid.
        if cap_data.bytes().is_empty() {
            return Err(Error::CapabilityEmpty);
        }
        let (cap_offset, tail_offset) = match self.last_capability {
            Some((offset, len)) => (Self::next_dword(offset, len), offset + 1),
            None => (FIRST_CAPABILITY_OFFSET, CAPABILITY_LIST_HEAD_OFFSET),
        };
        let end_offset = cap_offset
            .checked_add(total_len)
            .ok_or(Error::CapabilitySpaceFull(total_len))?;
        if end_offset > CAPABILITY_MAX_OFFSET {
            return Err(Error::CapabilitySpaceFull(total_len));
        }
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;
        self.write_byte_internal(tail_offset, cap_offset as u8, false);
        self.write_byte_internal(cap_offset, cap_data.id() as u8, false);
        self.write_byte_internal(cap_offset + 1, 0, false); // Next pointer.
        for (i, byte) in cap_data.bytes().iter().enumerate().skip(2) {
            self.write_byte_internal(cap_offset + i, *byte, false);
        }
        self.last_capability = Some((cap_offset, total_len));
        Ok(cap_offset)
    }

    // Find the next aligned offset after the one given.
    fn next_dword(offset: usize, len: usize) -> usize {
        let next = offset + len;
        (next + 3) & !3
    }

    /// Adds a region specified by `bar`.  Configures the specified BAR(s) to
    /// report this region and size to the guest kernel.  Enforces a few constraints
    /// (i.e, region size must be power of two, register not already used). Returns 'None' on
    /// failure all, `Some(BarIndex)` on success.
    pub fn add_pci_bar(&mut self, bar: &PciBar) -> Result<usize> {
        if self.bar_used[bar.reg_idx()] {
            return Err(Error::BarInUse(bar.reg_idx()));
        }

        if bar.size().count_ones() != 1 {
            return Err(Error::BarSizeInvalid(bar.size()));
        }

        if bar.reg_idx() >= NUM_BAR_REGS {
            return Err(Error::BarInvalid(bar.reg_idx()));
        }

        let bar_idx = BAR0_REG + bar.reg_idx();
        let end_addr = bar
            .addr()
            .checked_add(bar.size())
            .ok_or(Error::BarAddressInvalid(bar.addr(), bar.size()))?;
        match bar.region_type() {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::IORegion => {
                if end_addr > u64::from(u32::max_value()) {
                    return Err(Error::BarAddressInvalid(bar.addr(), bar.size()));
                }
            }
            PciBarRegionType::Memory64BitRegion => {
                if bar.reg_idx() + 1 >= NUM_BAR_REGS {
                    return Err(Error::BarInvalid64(bar.reg_idx()));
                }

                if end_addr > u64::max_value() {
                    return Err(Error::BarAddressInvalid(bar.addr(), bar.size()));
                }

                if self.bar_used[bar.reg_idx() + 1] {
                    return Err(Error::BarInUse64(bar.reg_idx()));
                }

                self.registers[bar_idx + 1] = (bar.addr() >> 32) as u32;
                self.writable_bits[bar_idx + 1] = !((bar.size() >> 32).wrapping_sub(1)) as u32;
                self.bar_used[bar.reg_idx() + 1] = true;
            }
        }

        let (mask, lower_bits) = match bar.region_type() {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => (
                BAR_MEM_ADDR_MASK,
                bar.prefetchable() as u32 | bar.region_type() as u32,
            ),
            PciBarRegionType::IORegion => (BAR_IO_ADDR_MASK, bar.region_type() as u32),
        };

        self.registers[bar_idx] = ((bar.addr() as u32) & mask) | lower_bits;
        self.writable_bits[bar_idx] = !(bar.size() - 1) as u32;
        self.bar_used[bar.reg_idx()] = true;
        Ok(bar.reg_idx())
    }


    // O(1) (O(n) 1<=n<=6) method to map a BAR index by an address.
    // This would be called by Device instance Read/Write methods.
    pub fn get_bar_idx_from_addr(&self, addr: u64) -> usize {
        let slice = &self.registers[BAR0_REG..];
        let mut reg_idx = 0;
        let mut iter = slice.iter();
        loop {
            if let Some(reg) = iter.next() {
                match reg & 0x111 {
                    x if x == PciBarRegionType::Memory32BitRegion as u32 ||
                         x == PciBarRegionType::Memory64BitRegion as u32 => {
                        let base = self.get_mem_bar_addr(reg_idx);
                        let size = self.get_bar_size(reg_idx);
                        if addr >= base && (base + size) > addr {
                            return reg_idx;
                        }
                        if x == PciBarRegionType::Memory64BitRegion as u32 {
                            iter.next();
                            reg_idx += 1;
                        }
                    }
                    x if x == PciBarRegionType::IORegion as u32 => {
                        let base = reg & BAR_IO_ADDR_MASK;
                        let size = (!self.writable_bits[reg_idx]).wrapping_add(1);
                        if (addr as u32) > base && (base + size) > (addr as u32) {
                            return reg_idx;
                        }
                    }
                    _ => return 0xff
                }
                reg_idx += 1;
            } else {
                break;
            }
        }
        0xff
    }

    /// Returns the address of the given Memory BAR region.
    pub fn get_mem_bar_addr(&self, bar_num: usize) -> u64 {
        let bar_idx = BAR0_REG + bar_num;

        match self.registers[bar_idx] & BAR_MEM_REGION_WIDTH_MASK {
            x if x == PciBarRegionType::Memory32BitRegion as u32 =>
                return (self.registers[bar_idx] & BAR_MEM_ADDR_MASK) as u64,
            x if x == PciBarRegionType::Memory64BitRegion as u32 =>
                return (self.registers[bar_idx + 1] as u64) << 32 |
                (self.registers[bar_idx] & BAR_MEM_ADDR_MASK) as u64,
            _ => u64::max_value(),
        }
    }

    /// Returns the size of the given BAR region.
    fn get_bar_size(&self, reg_idx: usize) -> u64 {
        let bar_idx = BAR0_REG + reg_idx;

        match self.registers[bar_idx] & BAR_MEM_REGION_WIDTH_MASK {
            x if x == PciBarRegionType::Memory32BitRegion as u32 =>
                return (!self.writable_bits[bar_idx]).wrapping_add(1) as u64,
            x if x == PciBarRegionType::Memory64BitRegion as u32 =>
                return ((!self.writable_bits[bar_idx + 1]).wrapping_add(1) as u64) << 32 |
                (!self.writable_bits[bar_idx]).wrapping_add(1) as u64,
            _ => u64::max_value(),
        }
    }

}

/// See pci_regs.h in kernel
#[derive(Copy, Clone)]
pub enum PciBarRegionType {
    Memory32BitRegion = 0,
    IORegion = 0x01,
    Memory64BitRegion = 0x04,
}

#[derive(Copy, Clone)]
pub enum PciBarPrefetchable {
    NotPrefetchable = 0,
    Prefetchable = 0x08,
}

pub trait PciBar: Send {
    fn set_address(&mut self, addr: Option<u64>);
    fn size(&self) -> u64;
    fn addr(&self) -> u64;
    fn reg_idx(&self) -> usize;
    fn region_type(&self) -> PciBarRegionType;
    fn prefetchable(&self) -> PciBarPrefetchable;
    /// Read the data from the address specified by the Bar with offset.
    fn read_bar(&self, offset: u64, data: &mut [u8]);
    /// Write the data to the address specified by the Bar with offset.
    fn write_bar(&mut self, offset: u64, data: &[u8]);
}
