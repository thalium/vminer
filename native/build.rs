fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/");

    let config = cbindgen::Config::from_file("cbindgen.toml").unwrap();

    cbindgen::Builder::new()
        .with_config(config)
        .with_crate(".")
        .generate()
        .unwrap()
        .write_to_file("icebox.h");
}
