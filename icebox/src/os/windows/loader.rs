use ibc::IceResult;
use std::{env, io::Read, path::PathBuf};

pub struct SymbolLoader {
    root: PathBuf,
    url_base: String,
}

impl SymbolLoader {
    pub fn with_default_root() -> IceResult<Self> {
        let path = match env::var_os("_NT_SYMBOl_PATH") {
            Some(path) => PathBuf::from(path),

            #[cfg(target_os = "windows")]
            None => PathBuf::from(r"C:\ProgramData\Dbg\sym"),

            #[cfg(not(target_os = "windows"))]
            None => {
                use ibc::ResultExt;
                match env::var_os("XDG_CACHE_HOME") {
                    Some(cache) => {
                        let mut cache = PathBuf::from(cache);
                        cache.push("PDB");
                        cache
                    }
                    None => {
                        let home = env::var_os("HOME").context("cannot find home directory")?;
                        let mut cache = PathBuf::from(home);
                        cache.push(".cache/PDB/");
                        cache
                    }
                }
            }
        };

        log::info!("Using PDB cache directory at {}", path.display());

        Self::with_root(path)
    }

    pub fn with_root(root: PathBuf) -> IceResult<Self> {
        Self::with_root_and_url(root, "https://msdl.microsoft.com/download/symbols".into())
    }

    pub fn with_root_and_url(root: PathBuf, url_base: String) -> IceResult<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self { root, url_base })
    }

    #[cfg(feature = "download_pdb")]
    fn download_pdb(
        &self,
        path: &std::path::Path,
        name: &str,
        id: &str,
    ) -> IceResult<ibc::ModuleSymbols> {
        // Download PDB
        let url = format!("{}/{name}/{id}/{name}", self.url_base);
        log::info!("Downloading {name}...");
        let mut pdb = Vec::new();
        ureq::get(&url)
            .call()
            .map_err(ibc::IceError::new)?
            .into_reader()
            .read_to_end(&mut pdb)?;

        // Save it to the filesystem
        let res = (|| {
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(path, &pdb)
        })();
        if let Err(err) = res {
            log::error!("Failed to write PDB at {}: {err}", path.display());
        }

        ibc::ModuleSymbols::from_bytes(&pdb)
    }
}

impl super::super::SymbolLoader for SymbolLoader {
    fn load(&self, name: &str, id: &str) -> IceResult<Option<ibc::ModuleSymbols>> {
        let components = [&*self.root, name.as_ref(), id.as_ref(), name.as_ref()];
        let path: PathBuf = components.iter().collect();

        if path.exists() {
            log::debug!("Using {}", path.display());
            ibc::ModuleSymbols::from_file(path).map(Some)
        } else {
            #[cfg(feature = "download_pdb")]
            match self.download_pdb(&path, name, id) {
                Ok(module) => Ok(Some(module)),
                Err(err) => {
                    log::error!("Failed to dowload PDB: {err}");
                    Ok(None)
                }
            }

            #[cfg(not(feature = "download_pdb"))]
            Ok(None)
        }
    }
}
