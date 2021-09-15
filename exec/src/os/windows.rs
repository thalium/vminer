use super::Os;

pub struct Windows;

impl Os for Windows {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_check() {
        let vm = crate::DumbDump::read("../linux.dump").unwrap();
        assert!(!Windows::quick_check(&vm).unwrap());

        let vm = crate::DumbDump::read("../grub.dump").unwrap();
        assert!(!Windows::quick_check(&vm).unwrap());
    }
}
