#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Dialect {
    Smb202 = 0x0202,
    Smb210 = 0x0210,
    Smb300 = 0x0300,
    Smb302 = 0x0302,
    Smb311 = 0x0311,
}
impl Dialect {
    pub fn from_u16(u: u16) -> Option<Dialect> {
        match u {
            0x0202 => Some(Dialect::Smb202),
            0x0210 => Some(Dialect::Smb210),
            0x0300 => Some(Dialect::Smb300),
            0x0302 => Some(Dialect::Smb302),
            0x0311 => Some(Dialect::Smb311),
            _ => None,
        }
    }
}
