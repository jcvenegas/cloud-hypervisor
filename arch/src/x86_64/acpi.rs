// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use acpi_tables::{
    rsdp::RSDP,
    sdt::{GenericAddress, SDT},
};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use vm_memory::{Address, ByteValued, Bytes};

use std::convert::TryInto;

use super::layout;

#[repr(packed)]
struct LocalAPIC {
    pub r#type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[repr(packed)]
#[derive(Default)]
struct IOAPIC {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

#[repr(packed)]
#[derive(Default)]
struct InterruptSourceOverride {
    pub r#type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[repr(packed)]
#[derive(Default)]
struct PCIRangeEntry {
    pub base_address: u64,
    pub segment: u16,
    pub start: u8,
    pub end: u8,
    _reserved: u32,
}

#[repr(packed)]
#[derive(Default)]
struct IortParavirtIommuNode {
    pub type_: u8,
    pub length: u16,
    pub revision: u8,
    _reserved1: u32,
    pub num_id_mappings: u32,
    pub ref_id_mappings: u32,
    pub device_id: u32,
    _reserved2: [u32; 3],
    pub model: u32,
    pub flags: u32,
    _reserved3: [u32; 4],
}

#[repr(packed)]
#[derive(Default)]
struct IortPciRootComplexNode {
    pub type_: u8,
    pub length: u16,
    pub revision: u8,
    _reserved1: u32,
    pub num_id_mappings: u32,
    pub ref_id_mappings: u32,
    pub mem_access_props: IortMemoryAccessProperties,
    pub ats_attr: u32,
    pub pci_seg_num: u32,
    pub mem_addr_size_limit: u8,
    _reserved2: [u8; 3],
}

#[repr(packed)]
#[derive(Default)]
struct IortMemoryAccessProperties {
    pub cca: u32,
    pub ah: u8,
    _reserved: u16,
    pub maf: u8,
}

#[repr(packed)]
#[derive(Default)]
struct IortIdMapping {
    pub input_base: u32,
    pub num_of_ids: u32,
    pub ouput_base: u32,
    pub output_ref: u32,
    pub flags: u32,
}

pub fn create_dsdt_table(
    serial_enabled: bool,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
) -> SDT {
    /*
        The hex tables in this file are generated from the ASL below with:
        "iasl -tc <dsdt.asl>"

        As the output contains a table header that is not required the first 36 bytes
        should be disregarded.
    */

    /*
    Device (_SB.PCI0)
        {
            Name (_HID, EisaId ("PNP0A08") /* PCI Express Bus */)  // _HID: Hardware ID
            Name (_CID, EisaId ("PNP0A03") /* PCI Bus */)  // _CID: Compatible ID
            Name (_ADR, Zero)  // _ADR: Address
            Name (_SEG, Zero)  // _SEG: PCI Segment
            Name (_UID, Zero)  // _UID: Unique ID
            Name (SUPP, Zero)
        }

        Scope (_SB.PCI0)
        {
            Name (_CRS, ResourceTemplate ()  // _CRS: Current Resource Settings
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    0x0000,             // Granularity
                    0x0000,             // Range Minimum
                    0x00FF,             // Range Maximum
                    0x0000,             // Translation Offset
                    0x0100,             // Length
                    ,, )
                IO (Decode16,
                    0x0CF8,             // Range Minimum
                    0x0CF8,             // Range Maximum
                    0x01,               // Alignment
                    0x08,               // Length
                    )
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000,             // Granularity
                    0x0000,             // Range Minimum
                    0x0CF7,             // Range Maximum
                    0x0000,             // Translation Offset
                    0x0CF8,             // Length
                    ,, , TypeStatic, DenseTranslation)
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000,             // Granularity
                    0x0D00,             // Range Minimum
                    0xFFFF,             // Range Maximum
                    0x0000,             // Translation Offset
                    0xF300,             // Length
                    ,, , TypeStatic, DenseTranslation)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                    0x00000000,         // Granularity
                    0x000A0000,         // Range Minimum
                    0x000BFFFF,         // Range Maximum
                    0x00000000,         // Translation Offset
                    0x00020000,         // Length
                    ,, , AddressRangeMemory, TypeStatic)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                    0x00000000,         // Granularity
                    0xC0000000,         // Range Minimum
                    0xFEBFFFFF,         // Range Maximum
                    0x00000000,         // Translation Offset
                    0x3EC00000,         // Length
                    ,, , AddressRangeMemory, TypeStatic)
                QWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                    0x0000000000000000, // Granularity
                    0x0000000800000000, // Range Minimum
                    0x0000000FFFFFFFFF, // Range Maximum
                    0x0000000000000000, // Translation Offset
                    0x0000000800000000, // Length
                    ,, , AddressRangeMemory, TypeStatic)
            })
        }
    */
    let mut pci_dsdt_data = [
        0x5Bu8, 0x82, 0x36, 0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x50, 0x43, 0x49, 0x30, 0x08, 0x5F, 0x48,
        0x49, 0x44, 0x0C, 0x41, 0xD0, 0x0A, 0x08, 0x08, 0x5F, 0x43, 0x49, 0x44, 0x0C, 0x41, 0xD0,
        0x0A, 0x03, 0x08, 0x5F, 0x41, 0x44, 0x52, 0x00, 0x08, 0x5F, 0x53, 0x45, 0x47, 0x00, 0x08,
        0x5F, 0x55, 0x49, 0x44, 0x00, 0x08, 0x53, 0x55, 0x50, 0x50, 0x00, 0x10, 0x41, 0x0B, 0x2E,
        0x5F, 0x53, 0x42, 0x5F, 0x50, 0x43, 0x49, 0x30, 0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x40,
        0x0A, 0x0A, 0x9C, 0x88, 0x0D, 0x00, 0x02, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x47, 0x01, 0xF8, 0x0C, 0xF8, 0x0C, 0x01, 0x08, 0x88, 0x0D, 0x00,
        0x01, 0x0C, 0x03, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x0C, 0x00, 0x00, 0xF8, 0x0C, 0x88, 0x0D,
        0x00, 0x01, 0x0C, 0x03, 0x00, 0x00, 0x00, 0x0D, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF3, 0x87,
        0x17, 0x00, 0x00, 0x0C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0xFF, 0xFF,
        0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x87, 0x17, 0x00, 0x00, 0x0C,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xFF, 0xFF, 0xBF, 0xFE, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xC0, 0x3E, 0x8A, 0x2B, 0x00, 0x00, 0x0C, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xFF, 0xFF,
        0xFF, 0xFF, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x79, 0x00,
    ];

    // Patch Range Minimum/Range Maximum/Length for the the 64-bit device area
    pci_dsdt_data[170..174].copy_from_slice(&layout::MEM_32BIT_DEVICES_START.0.to_le_bytes()[0..4]);
    pci_dsdt_data[174..178].copy_from_slice(
        &(layout::MEM_32BIT_DEVICES_START.0 + layout::MEM_32BIT_DEVICES_SIZE - 1).to_le_bytes()
            [0..4],
    );
    pci_dsdt_data[182..186].copy_from_slice(&layout::MEM_32BIT_DEVICES_SIZE.to_le_bytes()[0..4]);

    // Patch the Range Minimum/Range Maximum/Length for the the 64-bit device area
    pci_dsdt_data[200..208].copy_from_slice(&(start_of_device_area.0).to_le_bytes());
    pci_dsdt_data[208..216].copy_from_slice(&end_of_device_area.0.to_le_bytes());
    pci_dsdt_data[224..232].copy_from_slice(
        &(end_of_device_area.unchecked_offset_from(start_of_device_area) + 1).to_le_bytes(),
    );

    /*
    Device (_SB.MBRD)
    {
        Name (_HID, EisaId ("PNP0C02") /* PNP Motherboard Resources */)  // _HID: Hardware ID
        Name (_UID, Zero)  // _UID: Unique ID
    }

    Scope (_SB.MBRD)
    {
        Name (_CRS, ResourceTemplate ()  // _CRS: Current Resource Settings
        {
            Memory32Fixed (ReadWrite,
                0xE8000000,         // Address Base
                0x10000000,         // Address Length
                )
        })
    }
    */
    let mut mbrd_dsdt_data = [
        0x5Bu8, 0x82, 0x1A, 0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x4D, 0x42, 0x52, 0x44, 0x08, 0x5F, 0x48,
        0x49, 0x44, 0x0C, 0x41, 0xD0, 0x0C, 0x02, 0x08, 0x5F, 0x55, 0x49, 0x44, 0x00, 0x10, 0x21,
        0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x4D, 0x42, 0x52, 0x44, 0x08, 0x5F, 0x43, 0x52, 0x53, 0x11,
        0x11, 0x0A, 0x0E, 0x86, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x10,
        0x79, 0x00,
    ];

    mbrd_dsdt_data[52..56].copy_from_slice(&layout::PCI_MMCONFIG_START.0.to_le_bytes()[0..4]);
    mbrd_dsdt_data[56..60].copy_from_slice(&layout::PCI_MMCONFIG_SIZE.to_le_bytes()[0..4]);

    /*
    Device (_SB.COM1)
    {
        Name (_HID, EisaId ("PNP0501") /* 16550A-compatible COM Serial Port */)  // _HID: Hardware ID
        Name (_UID, Zero)  // _UID: Unique ID
        Name (_CRS, ResourceTemplate ()  // _CRS: Current Resource Settings
        {
            Interrupt (ResourceConsumer, Edge, ActiveHigh, Exclusive, ,, )
            {
                0x00000004,
            }
            IO (Decode16,
                0x03F8,             // Range Minimum
                0x03F8,             // Range Maximum
                0x00,               // Alignment
                0x08,               // Length
                )
        })
    }
    */
    let com1_dsdt_data = [
        0x5Bu8, 0x82, 0x36, 0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x43, 0x4F, 0x4D, 0x31, 0x08, 0x5F, 0x48,
        0x49, 0x44, 0x0C, 0x41, 0xD0, 0x05, 0x01, 0x08, 0x5F, 0x55, 0x49, 0x44, 0x00, 0x08, 0x5F,
        0x43, 0x52, 0x53, 0x11, 0x16, 0x0A, 0x13, 0x89, 0x06, 0x00, 0x03, 0x01, 0x04, 0x00, 0x00,
        0x00, 0x47, 0x01, 0xF8, 0x03, 0xF8, 0x03, 0x00, 0x08, 0x79, 0x00,
    ];

    /*
    Name (\_S5, Package (0x01)  // _S5_: S5 System State
    {
        0x05
    })
    */
    let s5_sleep_data = [0x08u8, 0x5F, 0x53, 0x35, 0x5F, 0x12, 0x04, 0x01, 0x0A, 0x05];

    // DSDT
    let mut dsdt = SDT::new(*b"DSDT", 36, 6, *b"CLOUDH", *b"CHDSDT  ", 1);
    dsdt.append(pci_dsdt_data);
    dsdt.append(mbrd_dsdt_data);
    if serial_enabled {
        dsdt.append(com1_dsdt_data);
    }
    dsdt.append(s5_sleep_data);

    dsdt
}
pub fn create_acpi_tables(
    guest_mem: &GuestMemoryMmap,
    num_cpus: u8,
    serial_enabled: bool,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    virt_iommu: Option<(u32, &[u32])>,
) -> GuestAddress {
    // RSDP is at the EBDA
    let rsdp_offset = layout::RSDP_POINTER;
    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let dsdt = create_dsdt_table(serial_enabled, start_of_device_area, end_of_device_area);
    let dsdt_offset = rsdp_offset.checked_add(RSDP::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = SDT::new(*b"FACP", 276, 6, *b"CLOUDH", *b"CHFACP  ", 1);

    // HW_REDUCED_ACPI and RESET_REG_SUP
    let fadt_flags: u32 = 1 << 20 | 1 << 10;
    facp.write(112, fadt_flags);

    // RESET_REG
    facp.write(116, GenericAddress::io_port_address(0x3c0));
    // RESET_VALUE
    facp.write(128, 1u8);

    facp.write(131, 3u8); // FADT minor version
    facp.write(140, dsdt_offset.0); // X_DSDT

    // SLEEP_CONTROL_REG
    facp.write(244, GenericAddress::io_port_address(0x3c0));
    // SLEEP_STATUS_REG
    facp.write(256, GenericAddress::io_port_address(0x3c0));

    facp.write(268, b"CLOUDHYP"); // Hypervisor Vendor Identity

    facp.update_checksum();
    let facp_offset = dsdt_offset.checked_add(dsdt.len() as u64).unwrap();
    guest_mem
        .write_slice(facp.as_slice(), facp_offset)
        .expect("Error writing FACP table");
    tables.push(facp_offset.0);

    // MADT
    let mut madt = SDT::new(*b"APIC", 44, 5, *b"CLOUDH", *b"CHMADT  ", 1);
    madt.write(36, layout::APIC_START);

    for cpu in 0..num_cpus {
        let lapic = LocalAPIC {
            r#type: 0,
            length: 8,
            processor_id: cpu,
            apic_id: cpu,
            flags: 1,
        };
        madt.append(lapic);
    }

    madt.append(IOAPIC {
        r#type: 1,
        length: 12,
        ioapic_id: 0,
        apic_address: layout::IOAPIC_START.0 as u32,
        gsi_base: 0,
        ..Default::default()
    });

    madt.append(InterruptSourceOverride {
        r#type: 2,
        length: 10,
        bus: 0,
        source: 4,
        gsi: 4,
        flags: 0,
    });

    let madt_offset = facp_offset.checked_add(facp.len() as u64).unwrap();
    guest_mem
        .write_slice(madt.as_slice(), madt_offset)
        .expect("Error writing MADT table");
    tables.push(madt_offset.0);

    // MCFG
    let mut mcfg = SDT::new(*b"MCFG", 36, 1, *b"CLOUDH", *b"CHMCFG  ", 1);

    // MCFG reserved 8 bytes
    mcfg.append(0u64);

    // 32-bit PCI enhanced configuration mechanism
    mcfg.append(PCIRangeEntry {
        base_address: layout::PCI_MMCONFIG_START.0,
        segment: 0,
        start: 0,
        end: 0xff,
        ..Default::default()
    });

    let mcfg_offset = madt_offset.checked_add(madt.len() as u64).unwrap();
    guest_mem
        .write_slice(mcfg.as_slice(), mcfg_offset)
        .expect("Error writing MCFG table");
    tables.push(mcfg_offset.0);

    let (prev_tbl_len, prev_tbl_off) = if let Some((iommu_id, dev_ids)) = &virt_iommu {
        // IORT
        let mut iort = SDT::new(*b"IORT", 36, 1, *b"CLOUDH", *b"CHIORT  ", 1);
        // IORT number of nodes
        iort.append(2u32);
        // IORT offset to array of IORT nodes
        iort.append(48u32);
        // IORT reserved 4 bytes
        iort.append(0u32);
        // IORT paravirtualized IOMMU node
        iort.append(IortParavirtIommuNode {
            type_: 128,
            length: 56,
            revision: 0,
            num_id_mappings: 0,
            ref_id_mappings: 56,
            device_id: *iommu_id,
            model: 1,
            ..Default::default()
        });

        let num_entries = dev_ids.len();
        let length: u16 = (36 + (20 * num_entries)).try_into().unwrap();

        // IORT PCI root complex node
        iort.append(IortPciRootComplexNode {
            type_: 2,
            length,
            revision: 0,
            num_id_mappings: num_entries as u32,
            ref_id_mappings: 36,
            ats_attr: 0,
            pci_seg_num: 0,
            mem_addr_size_limit: 255,
            ..Default::default()
        });

        for dev_id in dev_ids.iter() {
            // IORT ID mapping
            iort.append(IortIdMapping {
                input_base: *dev_id,
                num_of_ids: 1,
                ouput_base: *dev_id,
                output_ref: 48,
                flags: 0,
            });
        }

        let iort_offset = mcfg_offset.checked_add(mcfg.len() as u64).unwrap();
        guest_mem
            .write_slice(iort.as_slice(), iort_offset)
            .expect("Error writing IORT table");
        tables.push(iort_offset.0);

        (iort.len(), iort_offset)
    } else {
        (mcfg.len(), mcfg_offset)
    };

    // XSDT
    let mut xsdt = SDT::new(*b"XSDT", 36, 1, *b"CLOUDH", *b"CHXSDT  ", 1);
    for table in tables {
        xsdt.append(table);
    }
    xsdt.update_checksum();

    let xsdt_offset = prev_tbl_off.checked_add(prev_tbl_len as u64).unwrap();
    guest_mem
        .write_slice(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    // RSDP
    let rsdp = RSDP::new(*b"CLOUDH", xsdt_offset.0);
    guest_mem
        .write_slice(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
