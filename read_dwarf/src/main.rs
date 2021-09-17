use std::{fmt, fs};

use fallible_iterator::FallibleIterator;
use object::{Object, ObjectSection};

fn main() {
    let file = std::env::args_os().nth(1).expect("file name");
    let content = fs::read(&file).unwrap();
    let obj = object::File::parse(&*content).unwrap();

    parse_dwarf(&obj).unwrap();
}

fn parse_entry<R: gimli::Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
    debug_str: &gimli::DebugStr<R>,
    level: usize,
) -> gimli::Result<()>
where
    R::Offset: fmt::LowerHex,
{
    println!(
        "{:width$}{}: {:?}",
        "",
        entry.tag().static_string().unwrap(),
        entry.offset(),
        width = level * 2,
    );
    entry.attrs().for_each(|attr| {
        let name = attr.name().static_string().unwrap();
        //let value = match attr.string_value(debug_str) {
        //    Some(value) => value.to_string_lossy()?.to_string(),
        //    None => format!("{:?}", attr.value()),
        //};
        println!("{:width$}{}: {:?}", "", name, attr.value(), width = 2 * (level + 2));
        Ok(())
    })?;
    Ok(())
}

fn traverse_tree<R: gimli::Reader>(
    node: gimli::EntriesTreeNode<R>,
    debug_str: &gimli::DebugStr<R>,
    level: usize,
) -> gimli::Result<()>
where
    R::Offset: fmt::LowerHex,
{
    parse_entry(node.entry(), debug_str, level)?;

    let mut children = node.children();
    while let Some(child) = children.next()? {
        traverse_tree(child, debug_str, level + 1)?;
    }
    Ok(())
}

fn parse_dwarf(obj: &object::File) -> gimli::Result<()> {
    let endian = match obj.is_little_endian() {
        true => gimli::RunTimeEndian::Little,
        false => gimli::RunTimeEndian::Big,
    };

    let dwarf = gimli::Dwarf::load(|section| {
        if false {
            return Err(());
        }
        let data = obj
            .section_by_name(section.name())
            .map_or(Ok(&[][..]), |s| s.data())
            .unwrap();
        Ok(gimli::EndianSlice::new(data, endian))
        //.and_then(|s| s.data())
        //.unwrap_or(&[]))
        //.ok_or_else(|| format!("cannot find section {:?}", section.name()))
    })
    .unwrap();

    dwarf
        .units()
        .for_each(|unit| {
            println!("\n=== Parsing unit ===");
            println!("offset: {:?}\ntype: {:?}\n", unit.offset(), unit.version());
            let abbrs = unit.abbreviations(&dwarf.debug_abbrev)?;
            //let mut tree = unit.entries_tree(&abbrs, None)?;
            //traverse_tree(tree.root()?, &dwarf.debug_str, 0)?;

            let unit = dwarf.unit(unit)?;

            let mut entries = unit.entries();
            let mut level = 0;
            
            while let Some(()) = entries.next_entry()? {
                //level += delta;
                assert!(level >= 0);

                if let Some(entry) = entries.current() {
                    parse_entry(entry, &dwarf.debug_str, level as usize)?;
                }
            }

            Ok(())
        })
        .unwrap();


    // dwarf
    //     .units()
    //     .for_each(|unit_header| {
    //         println!("\n=== Parsing unit ===");
    //         println!("offset: {:?}\ntype: {:?}\n", unit_header.offset(), unit_header.version());
            
    //         let unit = dwarf.unit(unit_header).unwrap();

    //         dbg!(unit);

    //         Ok(())
    //     })
    //     .unwrap();

    /*
    let abbrev_section = obj.section_by_name(".debug_abbrev").unwrap();
    let content = abbrev_section.data().unwrap();
    let abbrev = gimli::read::DebugAbbrev::new(content, gimli::LittleEndian);
    let debug_abbrev_offset = abbrev.off
    let abbrev = abbrev.abbreviations(debug_abbrev_offset).unwrap();
    */

    Ok(())
}
