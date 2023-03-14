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
    num_symbol_table_entry: usize,
    string_table: StringTable<'a>,
    string_table_data: Vec<u8>,
    symbol_table_file_offset: u64,
    section_file_offset: Vec<u64>,
    section_address: Vec<u64>,
}

impl<'a> XcoffObjectWriter<'a> {
    fn get_section_flags(section: &Section<'a>) -> Result<u16> {
        return Ok(match section.kind {
            SectionKind::Text => xcoff::STYP_TEXT,
            SectionKind::Data => xcoff::STYP_DATA,
            SectionKind::UninitializedData => xcoff::STYP_BSS,
            SectionKind::OtherString => xcoff::STYP_INFO,
            SectionKind::Tls => xcoff::STYP_TDATA,
            SectionKind::UninitializedTls => xcoff::STYP_TBSS,
            SectionKind::Debug => xcoff::STYP_DEBUG,
            _ => match section.flags {
                SectionFlags::Xcoff { s_flags } => s_flags as u16,
                _ => return Err(Error(format!("Unhandled section kind: {:?}", section.kind))),
            },
        });
    }

    fn finalize_string_table(&mut self) {
        // The first 4-bytes contains the total length(including the prefixed 4-bytes)
        // of the string table.
        self.string_table_data.append(&mut vec![0u8; 4]);
        self.string_table.write(4, &mut self.string_table_data);
        let length_field = u32::to_be_bytes(self.string_table_data.len() as u32);
        self.string_table_data[0..4].copy_from_slice(&length_field);
    }

    fn layout(&mut self) -> Result<()> {
        // FIXME: Relocation is not supported yet.
        let mut object_file_offset: u64 = 0;
        let (header_size, section_header_size, _, symbol_size) = (
            mem::size_of::<xcoff::FileHeader64>(),
            mem::size_of::<xcoff::SectionHeader64>(),
            mem::size_of::<xcoff::Rel64>(),
            mem::size_of::<xcoff::Symbol64>(),
        );
        object_file_offset += header_size as u64;
        let mut address: u64 = 0;
        // FIXME: Shall we handle section alignment?
        object_file_offset += (section_header_size * self.object.sections.len()) as u64;
        for (index, section) in self.object.sections.iter().enumerate() {
            self.string_table.add(&section.name);
            self.section_address[index] = address;
            self.section_file_offset[index] = object_file_offset;
            address += section.size;
            object_file_offset += section.size;
        }
        self.symbol_table_file_offset = object_file_offset;
        for (_, symbol) in self.object.symbols.iter().enumerate() {
            self.string_table.add(&symbol.name);
            self.num_symbol_table_entry += match symbol.kind {
                SymbolKind::Section => 2,
                _ => 1,
            };
        }
        object_file_offset += (symbol_size * self.num_symbol_table_entry) as u64;
        self.finalize_string_table();
        object_file_offset += self.string_table_data.len() as u64;
        self.buffer
            .reserve(object_file_offset as usize)
            .map_err(|_| Error(String::from("Cannot allocate buffer")))?;
        return Ok(());
    }

    fn write_file_header(&mut self) -> Result<()> {
        debug_assert_eq!(self.buffer.len(), 0);
        //debug_assert_eq!(mem::size_of::<xcoff::FileHeader64>(), 0);
        self.buffer.write(&xcoff::FileHeader64 {
            f_magic: U16::new(BE, xcoff::MAGIC_64),
            f_nscns: U16::new(BE, self.section_address.len() as u16),
            f_timdat: U32::new(BE, 0),
            f_symptr: U64::new(BE, self.symbol_table_file_offset as u64),
            f_nsyms: U32::new(BE, self.num_symbol_table_entry as u32),
            f_opthdr: U16::new(BE, 0),
            f_flags: match self.object.flags {
                FileFlags::Xcoff { f_flags } => U16::new(BE, f_flags),
                _ => U16::default(),
            },
        });
        return Ok(());
    }

    fn write_aux_file_header(&self) -> Result<()> {
        return Ok(());
    }

    fn write_section_header_table(&mut self) -> Result<()> {
        for (index, section) in self.object.sections.iter().enumerate() {
            let mut s_name = [0u8; 8];
            s_name
                .get_mut(..section.name.len())
                .ok_or_else(|| {
                    Error(format!(
                        "Section name `{}` is too long",
                        section.name().unwrap_or(""),
                    ))
                })?
                .copy_from_slice(&section.name);
            let s_flags = Self::get_section_flags(section)?;
            let section_header = xcoff::SectionHeader64 {
                s_name: s_name,
                s_paddr: U64::new(BE, self.section_address[index]),
                s_vaddr: U64::new(BE, self.section_address[index]),
                s_size: U64::new(BE, section.size),
                s_scnptr: U64::new(BE, self.section_file_offset[index]),
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
        for (index, section) in self.object.sections.iter().enumerate() {
            let section_file_offset = self.section_file_offset[index];
            debug_assert_eq!(self.buffer.len() as u64, section_file_offset);
            self.buffer.write_bytes(&section.data);
        }
        return Ok(());
    }

    fn write_relocations(&self) -> Result<()> {
        return Ok(());
    }

    fn write_symbol_table(&mut self) -> Result<()> {
        debug_assert_eq!(self.symbol_table_file_offset, self.buffer.len() as u64);
        for (_, symbol) in self.object.symbols.iter().enumerate() {
            let n_offset =
                self.string_table
                    .get_offset(self.string_table.get_id(&symbol.name)) as u32;
            if let SymbolSection::Section(section_id) = symbol.section {
                let section = self.object.section(section_id);
                let (n_sclass, n_numaux, x_smtyp, x_smclas) = match symbol.kind {
                    SymbolKind::Section => {
                        let sc = if symbol.weak {
                            xcoff::C_WEAKEXT
                        } else if symbol.is_undefined() {
                            xcoff::C_HIDEXT
                        } else {
                            xcoff::C_EXT
                        };
                        let smt = xcoff::XTY_SD;
                        let smc = if section.kind == SectionKind::Data {
                            xcoff::XMC_RW
                        } else {
                            xcoff::XMC_PR
                        };
                        (sc, 1, smt, smc)
                    }
                    SymbolKind::File => (xcoff::C_FILE, 0, 0, 0),
                    _ => (xcoff::C_INFO, 0, 0, 0),
                };
                let symbol_entry = xcoff::Symbol64 {
                    n_value: U64::new(BE, symbol.value),
                    n_offset: U32::new(BE, n_offset),
                    n_scnum: I16::new(BE, (section_id.0 + 1) as i16),
                    n_type: U16::new(BE, 0),
                    n_sclass: n_sclass,
                    n_numaux: n_numaux,
                };
                self.buffer.write(&symbol_entry);
                match n_numaux {
                    0 => {}
                    1 => {
                        let csect = xcoff::CsectAux64 {
                            x_scnlen_lo: U32::new(BE, symbol.size as u32),
                            x_scnlen_hi: U32::new(BE, (symbol.size >> 32) as u32),
                            x_snhash: U16::new(BE, 0),
                            x_parmhash: U32::new(BE, 0),
                            x_smtyp: x_smtyp,
                            x_smclas: x_smclas,
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
            } else {
                return Err(Error(format!(
                    "Unable to handle symbol {:?} which doesn't belong to any section",
                    symbol
                )));
            }
        }
        return Ok(());
    }

    fn write_string_table(&mut self) -> Result<()> {
        self.buffer.write_bytes(&self.string_table_data);
        return Ok(());
    }

    fn write(&mut self) -> Result<()> {
        // FIXME: XCOFF32 is not supported yet.
        if !self.is_64 {
            return Err(Error(format!(
                "Writing XCOFF32 object file is not supported yet."
            )));
        }
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
            StandardSection::ReadOnlyData | StandardSection::ReadOnlyDataWithRel => {
                // Unsupported section.
                (&[], &[], SectionKind::ReadOnlyData)
            }
            StandardSection::ReadOnlyString => {
                // Unsupported section.
                (&[], &[], SectionKind::ReadOnlyString)
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
            section_file_offset: vec![0; self.sections.len()],
            section_address: vec![0; self.sections.len()],
        };
        return xcoff.write();
    }
}
