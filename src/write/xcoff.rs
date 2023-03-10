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
    num_sections: usize,
    symbol_table_offset: usize,
    num_symbol_table_entry: usize,
    string_table_offset: usize,
    string_table: StringTable<'a>,
    string_table_data: Vec<u8>,
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
        for (_, section) in self.object.sections.iter().enumerate() {}
        for (_, symbol) in self.object.symbols.iter().enumerate() {
            self.string_table.add(&symbol.name);
        }
        self.finalize_string_table();
        return Ok(());
    }

    fn write_file_header(&mut self) -> Result<()> {
        if self.is_64 {
            self.buffer.write(&xcoff::FileHeader64 {
                f_magic: U16::new(BE, xcoff::MAGIC_64),
                f_nscns: U16::new(BE, self.num_sections as u16),
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
                f_nscns: U16::new(BE, self.num_sections as u16),
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
            num_sections: 0,
            num_symbol_table_entry: 0,
            symbol_table_offset: 0,
            string_table_offset: 0,
            string_table: StringTable::default(),
            string_table_data: Vec::new(),
        };
        return xcoff.write();
    }
}
