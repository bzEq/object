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
    symbol_table_offset: usize,
    num_symbol_table_entry: usize,
    string_table_offset: usize,
    string_table: StringTable<'a>,
    string_table_data: Vec<u8>,
    symbol_section: HashMap<SymbolId, XcoffSectionIndex>,
    section_offset: HashMap<XcoffSectionIndex, usize>,
    csect_group: HashMap<XcoffSectionIndex, Vec<SectionId>>,
    csect_offset: HashMap<SectionId, usize>,
    // C_INFO symbol's offset in .info section.
    info_symbol_offset: HashMap<SymbolId, usize>,
    filenames: Vec<SymbolId>,
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
        let prefix_bytes = u32::to_be_bytes(self.string_table_data.len() as u32);
        self.string_table_data[0..4].copy_from_slice(&prefix_bytes);
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
                _ => {}
            }
        }
        for i in (XcoffSectionIndex::Text as i32)..(XcoffSectionIndex::Info as i32 + 1) {
            let csect_group = &self
                .csect_group
                .get(&(XcoffSectionIndex::from_i32(i)))
                .unwrap();
            for id in csect_group.iter() {
                let section = self.object.section(*id);
                let section_align = std::cmp::max(section.align, default_section_align);
                object_file_offset = align(object_file_offset, section_align as usize);
                self.csect_offset.insert(*id, object_file_offset);
                object_file_offset += section.size as usize;
            }
        }
        // FIXME: Currently we only support C_INFO symbols which is a reference to
        // data stored in XCOFF's .info section. For these C_INFO symbols, we currently
        // set their visibility to SYM_V_INTERNAL.
        let mut info_symbol_offset = 0;
        for (_, symbol) in self.object.symbols.iter().enumerate() {
            self.string_table.add(&symbol.name);
            if symbol.kind == SymbolKind::File {
                let sym_id = self.object.symbol_id(&symbol.name).unwrap();
                self.filenames.push(sym_id);
                continue;
            }
            match symbol.section {
                SymbolSection::Section(id) => {
                    // We currently only handle symbols defined in .info section.
                    // FIXME: For other symbols, we may map them to XCOFF's csect and create
                    // auxiliar entries for them.
                    if self
                        .csect_group
                        .get(&XcoffSectionIndex::Info)
                        .unwrap()
                        .contains(&id)
                    {
                        if let Some(sym_id) = self.object.symbol_id(&symbol.name) {
                            self.info_symbol_offset.insert(sym_id, info_symbol_offset);
                            // For C_INFO symbol's data, it's prefixed with a word indicating
                            // the data's length.
                            info_symbol_offset += 4 + symbol.size as usize;
                            // C_INFO symbol doesn't have auxiliary entry.
                            self.num_symbol_table_entry += 1;
                            self.symbol_section.insert(sym_id, XcoffSectionIndex::Info);
                        }
                    }
                }
                _ => {}
            }
        }
        // If no file symbol exists, we add one to make AIX toolchain happy.
        if self.filenames.is_empty() {
            self.num_symbol_table_entry += 1;
        }
        self.symbol_table_offset = object_file_offset;
        object_file_offset += symbol_size * self.num_symbol_table_entry;
        self.finalize_string_table();
        self.string_table_offset = object_file_offset;
        return Ok(());
    }

    fn write_file_header(&mut self) -> Result<()> {
        if self.is_64 {
            self.buffer.write(&xcoff::FileHeader64 {
                f_magic: U16::new(BE, xcoff::MAGIC_64),
                f_nscns: U16::new(BE, self.csect_group.len() as u16),
                f_timdat: U32::new(BE, 0),
                f_symptr: U64::new(BE, self.symbol_table_offset as u64),
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
                f_symptr: U32::new(BE, self.symbol_table_offset as u32),
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

    fn write_section_header_table(&self) -> Result<()> {
        // FIXME: Write DwarfSection, OverflowSection and ExceptionSection.
        return Ok(());
    }

    fn write_sections(&self) -> Result<()> {
        // FIXME: Write DwarfSection and ExceptionSection.
        return Ok(());
    }

    fn write_relocations(&self) -> Result<()> {
        return Ok(());
    }

    fn write_symbol_table(&self) -> Result<()> {
        return Ok(());
    }

    fn write_string_table(&mut self) -> Result<()> {
        debug_assert_eq!(self.buffer.len(), self.string_table_offset);
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
    pub(crate) fn xcoff_write(&self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        let mut xcoff = XcoffObjectWriter {
            object: self,
            buffer: buffer,
            is_64: is_64(self),
            num_symbol_table_entry: 0,
            symbol_table_offset: 0,
            string_table_offset: 0,
            string_table: StringTable::default(),
            string_table_data: Vec::new(),
            csect_group: HashMap::new(),
            csect_offset: HashMap::new(),
            info_symbol_offset: HashMap::new(),
            section_offset: HashMap::new(),
            symbol_section: HashMap::new(),
            filenames: Vec::new(),
        };
        return xcoff.write();
    }
}
