//! Helper for writing XCOFF files.
use core::mem;

use crate::endian::{BigEndian as BE, I16, U16, U32};
use crate::write::string::*;
use crate::write::util::*;
use crate::write::*;

use crate::{xcoff, AddressSize};

struct XcoffObjectWriter<'a> {
    object: &'a Object<'a>,
    buffer: &'a mut dyn WritableBuffer,

    is_64: bool,
    symbol_table_file_offset: usize,
    num_symbol_table_entry: usize,
    string_table: StringTable<'a>,
    string_table_data: Vec<u8>,
    symbol_section: Vec<(SymbolId, XcoffSectionIndex)>,
    section_file_offset: HashMap<XcoffSectionIndex, usize>,
    section_size: HashMap<XcoffSectionIndex, usize>,
    section_address: HashMap<XcoffSectionIndex, u64>,
    csect_group: HashMap<XcoffSectionIndex, Vec<SectionId>>,
    csect_file_offset: HashMap<SectionId, usize>,
    csect_address: HashMap<SectionId, u64>,
    // C_INFO symbol's offset in .info section.
    info_symbol_offset: HashMap<SymbolId, usize>,
    filenames: Vec<&'a Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum XcoffSectionIndex {
    Text = 1,
    Data,
    Info,
}

impl XcoffSectionIndex {
    fn from_i32(i: i32) -> Self {
        match i {
            1 => XcoffSectionIndex::Text,
            2 => XcoffSectionIndex::Data,
            3 => XcoffSectionIndex::Info,
            _ => panic!("Out of bound index"),
        }
    }
}

impl<'a> XcoffObjectWriter<'a> {
    fn finalize_string_table(&mut self) {
        // The first 4-bytes contains the total length(including the prefixed 4-bytes)
        // of the string table.
        self.string_table_data.append(&mut vec![0u8; 4]);
        self.string_table.write(4, &mut self.string_table_data);
        let length_field = u32::to_be_bytes(self.string_table_data.len() as u32);
        self.string_table_data[0..4].copy_from_slice(&length_field);
    }

    fn layout(&mut self) -> Result<()> {
        // Add .text and .data XCOFF sections to make AIX toolchain happy.
        // Add .info XCOFF section to store rust metadata.
        self.csect_group.insert(XcoffSectionIndex::Text, Vec::new());
        self.csect_group.insert(XcoffSectionIndex::Data, Vec::new());
        self.csect_group.insert(XcoffSectionIndex::Info, Vec::new());
        let num_sections = self.csect_group.len();
        // FIXME: Relocation is not supported yet.
        let mut object_file_offset = 0;
        let (header_size, section_header_size, _, symbol_size) = if self.is_64 {
            (
                mem::size_of::<xcoff::FileHeader64>(),
                mem::size_of::<xcoff::SectionHeader64>(),
                mem::size_of::<xcoff::Rel64>(),
                mem::size_of::<xcoff::Symbol64>(),
            )
        } else {
            (
                mem::size_of::<xcoff::FileHeader32>(),
                mem::size_of::<xcoff::SectionHeader32>(),
                mem::size_of::<xcoff::Rel32>(),
                mem::size_of::<xcoff::Symbol32>(),
            )
        };
        object_file_offset += header_size;
        // FIXME: Support auxiliary file header for XCOFF32.
        object_file_offset += section_header_size * num_sections;
        // For every section in object.sections, we treat it as a csect(control section).
        let default_section_align = 4;
        for (id, section) in self.object.sections.iter().enumerate() {
            self.string_table.add(&section.name);
            // Currently, we only support SetionKind::OtherString which is mapped to
            // XCOFF's .info section, i.e., comment section.
            match section.kind {
                SectionKind::OtherString => {
                    self.csect_group
                        .get_mut(&XcoffSectionIndex::Info)
                        .unwrap()
                        .push(SectionId(id));
                }
                SectionKind::Data => {
                    self.csect_group
                        .get_mut(&XcoffSectionIndex::Data)
                        .unwrap()
                        .push(SectionId(id));
                }
                SectionKind::Text => {
                    self.csect_group
                        .get_mut(&XcoffSectionIndex::Text)
                        .unwrap()
                        .push(SectionId(id));
                }
                _ => {}
            }
        }
        let mut address: u64 = 0;
        for i in (XcoffSectionIndex::Text as i32)..(XcoffSectionIndex::Info as i32 + 1) {
            let index = XcoffSectionIndex::from_i32(i);
            let csect_group = &self.csect_group.get(&index).unwrap();
            let section_start = address;
            self.section_file_offset.insert(index, object_file_offset);
            self.section_address.insert(index, address);
            for id in csect_group.iter() {
                let section = self.object.section(*id);
                let section_align = std::cmp::max(section.align, default_section_align);
                address = align_u64(address, section_align as u64);
                self.csect_address.insert(*id, address);
                if index == XcoffSectionIndex::Info {
                    address += 4 + (section.size as u64);
                } else {
                    address += section.size as u64;
                }
            }
            address = align_u64(address, default_section_align as u64);
            let section_size = (address - section_start) as usize;
            self.section_size.insert(index, section_size);
            object_file_offset += section_size;
        }
        // FIXME: Currently we only support C_INFO symbols which is a reference to
        // data stored in XCOFF's .info section.
        self.symbol_table_file_offset = object_file_offset;
        let mut info_symbol_offset = 0;
        for (_, symbol) in self.object.symbols.iter().enumerate() {
            self.string_table.add(&symbol.name);
            if symbol.kind == SymbolKind::File {
                self.filenames.push(&symbol.name);
                continue;
            }
            match symbol.section {
                SymbolSection::Section(id) => {
                    if let Some(symbol_id) = self.object.symbol_id(&symbol.name) {
                        let index = match symbol.kind {
                            SymbolKind::Text => XcoffSectionIndex::Text,
                            SymbolKind::Data => XcoffSectionIndex::Data,
                            _ => XcoffSectionIndex::Info,
                        };
                        if index == XcoffSectionIndex::Info {
                            // For C_INFO symbol's data, it's prefixed with a word indicating
                            // the data's length. However the data the symbol points
                            // to starts after the word.
                            self.info_symbol_offset
                                .insert(symbol_id, info_symbol_offset + 4);
                            info_symbol_offset += 4 + symbol.size as usize;
                            // C_INFO symbol doesn't have auxiliary entry.
                            self.num_symbol_table_entry += 1;
                        } else {
                            // Other symbol has one extra auxiliary entry.
                            self.num_symbol_table_entry += 2;
                        }
                        self.symbol_section.push((symbol_id, index));
                    }
                }
                _ => {}
            }
        }
        // If no file symbol exists, we add one to make AIX toolchain happy.
        if self.filenames.is_empty() {
            self.num_symbol_table_entry += 1;
        }
        object_file_offset += symbol_size * self.num_symbol_table_entry;
        self.finalize_string_table();
        return Ok(());
    }

    fn write_file_header(&mut self) -> Result<()> {
        if self.is_64 {
            self.buffer.write(&xcoff::FileHeader64 {
                f_magic: U16::new(BE, xcoff::MAGIC_64),
                f_nscns: U16::new(BE, self.csect_group.len() as u16),
                f_timdat: U32::new(BE, 0),
                f_symptr: U64::new(BE, self.symbol_table_file_offset as u64),
                f_nsyms: U32::new(BE, self.num_symbol_table_entry as u32),
                f_opthdr: U16::new(BE, 0),
                f_flags: match self.object.flags {
                    FileFlags::Xcoff { f_flags } => U16::new(BE, f_flags),
                    _ => U16::default(),
                },
            });
        } else {
            self.buffer.write(&xcoff::FileHeader32 {
                f_magic: U16::new(BE, xcoff::MAGIC_32),
                f_nscns: U16::new(BE, self.csect_group.len() as u16),
                f_timdat: U32::new(BE, 0),
                f_symptr: U32::new(BE, self.symbol_table_file_offset as u32),
                f_nsyms: U32::new(BE, self.num_symbol_table_entry as u32),
                f_opthdr: U16::new(BE, 0),
                f_flags: match self.object.flags {
                    FileFlags::Xcoff { f_flags } => U16::new(BE, f_flags),
                    _ => U16::default(),
                },
            });
        }
        return Ok(());
    }

    fn write_aux_file_header(&self) -> Result<()> {
        if self.is_64 {
            return Ok(());
        }
        return Err(Error(String::from(
            "Auxiliary header not implemented for XCOFF32",
        )));
    }

    fn write_section_header_table(&mut self) -> Result<()> {
        for i in (XcoffSectionIndex::Text as i32)..(XcoffSectionIndex::Info as i32 + 1) {
            let index = XcoffSectionIndex::from_i32(i);
            let (s_flags, name) = match index {
                XcoffSectionIndex::Text => (xcoff::STYP_TEXT, b".text"),
                XcoffSectionIndex::Data => (xcoff::STYP_DATA, b".data"),
                XcoffSectionIndex::Info => (xcoff::STYP_INFO, b".info"),
            };
            let mut s_name = [0u8; 8];
            s_name[..name.len()].copy_from_slice(name);
            // FIXME: Support XCOFF32.
            let section_header = xcoff::SectionHeader64 {
                s_name: s_name,
                s_paddr: U64::new(BE, *self.section_address.get(&index).unwrap()),
                s_vaddr: U64::new(BE, *self.section_address.get(&index).unwrap()),
                s_size: U64::new(BE, (*self.section_size.get(&index).unwrap()) as u64),
                s_scnptr: U64::new(BE, (*self.section_file_offset.get(&index).unwrap()) as u64),
                s_relptr: U64::new(BE, 0),
                s_lnnoptr: U64::new(BE, 0),
                s_nreloc: U32::new(BE, 0),
                s_nlnno: U32::new(BE, 0),
                s_flags: U32::new(BE, s_flags as u32),
                s_reserve: U32::new(BE, 0),
            };
            self.buffer.write(&section_header);
        }
        return Ok(());
    }

    fn write_sections(&mut self) -> Result<()> {
        for i in (XcoffSectionIndex::Text as i32)..(XcoffSectionIndex::Info as i32 + 1) {
            let index = XcoffSectionIndex::from_i32(i);
            let section_file_offset = *self.section_file_offset.get(&index).unwrap();
            let section_address = *self.section_address.get(&index).unwrap();
            debug_assert_eq!(self.buffer.len(), section_file_offset);
            let csect_group = &self.csect_group.get(&index).unwrap();
            for id in csect_group.iter() {
                let section = self.object.section(*id);
                let csect_address = *self.csect_address.get(id).unwrap();
                debug_assert!(section_address <= csect_address);
                let csect_file_offset =
                    section_file_offset + ((csect_address - section_address) as usize);
                let padding = vec![0u8; csect_file_offset - self.buffer.len()];
                self.buffer.write_bytes(&padding);
                if index == XcoffSectionIndex::Info {
                    let length_field = u32::to_be_bytes(section.size as u32);
                    self.buffer.write_bytes(&length_field);
                }
                self.buffer.write_bytes(&section.data);
            }
        }
        return Ok(());
    }

    fn write_relocations(&self) -> Result<()> {
        return Ok(());
    }

    fn write_symbol_table(&mut self) -> Result<()> {
        debug_assert_eq!(self.symbol_table_file_offset, self.buffer.len());
        if self.filenames.is_empty() {
        } else {
            for symbol_id in self.filenames.iter() {}
        }
        for (symbol_id, index) in self.symbol_section.iter() {
            let symbol = self.object.symbol(*symbol_id);
            match symbol.section {
                SymbolSection::Section(id) => {
                    let section = self.object.section(id);
                    let (storage_class, n_numaux, symbol_type, storage_mapping_class) = match index
                    {
                        XcoffSectionIndex::Data | XcoffSectionIndex::Text => {
                            let sc = if symbol.weak {
                                xcoff::C_WEAKEXT
                            } else if symbol.is_undefined() {
                                xcoff::C_HIDEXT
                            } else {
                                xcoff::C_EXT
                            };
                            let st = xcoff::XTY_SD;
                            let smc = if *index == XcoffSectionIndex::Data {
                                xcoff::XMC_RW
                            } else {
                                xcoff::XMC_PR
                            };
                            (sc, 1, st, smc)
                        }
                        XcoffSectionIndex::Info => (xcoff::C_INFO, 0, 0, 0),
                    };
                    // FIXME: Fill relocatable address for Text and Data symbols.
                    let n_value = match storage_class {
                        xcoff::C_INFO => *(self.info_symbol_offset.get(symbol_id).unwrap()) as u64,
                        _ => symbol.value,
                    };
                    let n_offset = self
                        .string_table
                        .get_offset(self.string_table.get_id(&symbol.name))
                        as u32;
                    // FIXME: Support XCOFF32.
                    let symbol_entry = xcoff::Symbol64 {
                        n_value: U64::new(BE, n_value),
                        n_offset: U32::new(BE, n_offset),
                        n_scnum: I16::new(BE, *index as i16),
                        n_type: U16::new(BE, 0),
                        n_sclass: storage_class,
                        n_numaux: n_numaux,
                    };
                    self.buffer.write(&symbol_entry);
                    // Write auxiliary entry.
                    match n_numaux {
                        0 => {}
                        1 => {
                            let csect = xcoff::CsectAux64 {
                                x_scnlen_lo: U32::new(BE, symbol.size as u32),
                                x_scnlen_hi: U32::new(BE, (symbol.size >> 32) as u32),
                                x_snhash: U16::new(BE, 0),
                                x_parmhash: U32::new(BE, 0),
                                x_smtyp: symbol_type,
                                x_smclas: storage_mapping_class,
                                pad: 0,
                                x_auxtype: xcoff::AUX_CSECT,
                            };
                            self.buffer.write(&csect);
                        }
                        _ => {
                            return Err(Error(format!(
                                "Unexpected number of auxiliary entries: {}",
                                n_numaux
                            )));
                        }
                    }
                }
                _ => {
                    return Err(Error(format!(
                        "Symbol {} doesn't have a csect!",
                        symbol.name().unwrap_or("")
                    )));
                }
            }
        }
        return Ok(());
    }

    fn write_string_table(&mut self) -> Result<()> {
        self.buffer.write_bytes(&self.string_table_data);
        return Ok(());
    }

    fn write(&mut self) -> Result<()> {
        self.layout()?;
        self.write_file_header()?;
        self.write_aux_file_header()?;
        self.write_section_header_table()?;
        self.write_sections()?;
        self.write_relocations()?;
        self.write_symbol_table()?;
        return self.write_string_table();
    }
}

fn is_64(object: &Object) -> bool {
    match object.architecture.address_size().unwrap() {
        AddressSize::U64 => true,
        _ => false,
    }
}

impl<'a> Object<'a> {
    pub(crate) fn xcoff_section_info(
        &self,
        section: StandardSection,
    ) -> (&'static [u8], &'static [u8], SectionKind) {
        match section {
            StandardSection::Text => (&[], &b".text"[..], SectionKind::Text),
            StandardSection::Data => (&[], &b".data"[..], SectionKind::Data),
            StandardSection::ReadOnlyData
            | StandardSection::ReadOnlyDataWithRel
            | StandardSection::ReadOnlyString => (&[], &b".rdata"[..], SectionKind::ReadOnlyData),
            StandardSection::UninitializedData => {
                (&[], &b".bss"[..], SectionKind::UninitializedData)
            }
            StandardSection::Tls => (&[], &b".tdata"[..], SectionKind::Tls),
            StandardSection::UninitializedTls => {
                (&[], &b".tbss"[..], SectionKind::UninitializedTls)
            }
            StandardSection::TlsVariables => {
                // Unsupported section.
                (&[], &[], SectionKind::TlsVariables)
            }
            StandardSection::Common => {
                // Unsupported section.
                (&[], &[], SectionKind::Common)
            }
        }
    }

    pub(crate) fn xcoff_fixup_relocation(&mut self, mut relocation: &mut Relocation) -> i64 {
        let constant = match relocation.kind {
            RelocationKind::Relative => relocation.addend + 4,
            _ => relocation.addend,
        };
        relocation.addend -= constant;
        constant
    }

    pub(crate) fn xcoff_write(&self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        let mut xcoff = XcoffObjectWriter {
            object: self,
            buffer: buffer,
            is_64: is_64(self),
            num_symbol_table_entry: 0,
            symbol_table_file_offset: 0,
            string_table: StringTable::default(),
            string_table_data: Vec::new(),
            csect_group: HashMap::new(),
            csect_file_offset: HashMap::new(),
            csect_address: HashMap::new(),
            info_symbol_offset: HashMap::new(),
            section_file_offset: HashMap::new(),
            section_size: HashMap::new(),
            section_address: HashMap::new(),
            symbol_section: Vec::new(),
            filenames: Vec::new(),
        };
        return xcoff.write();
    }
}
