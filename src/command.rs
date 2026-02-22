#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum Command {
    Negotiate = 0x0,
    SessionSetup = 0x1,
    Logoff = 0x2,
    TreeConnect = 0x3,
    TreeDisconnect = 0x4,
    Create = 0x5,
    Close = 0x6,
    Flush = 0x7,
    Read = 0x8,
    Write = 0x9,
    Lock = 0xA,
    IoCtl = 0xB,
    Cancel = 0xC,
    Echo = 0xD,
    QueryDirectory = 0xE,
    ChangeNotify = 0xF,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
}
impl Command {
    pub fn from_u16(u: u16) -> Option<Self> {
        match u {
            0x0 => Some(Self::Negotiate),
            0x1 => Some(Self::SessionSetup),
            0x2 => Some(Self::Logoff),
            0x3 => Some(Self::TreeConnect),
            0x4 => Some(Self::TreeDisconnect),
            0x5 => Some(Self::Create),
            0x6 => Some(Self::Close),
            0x7 => Some(Self::Flush),
            0x8 => Some(Self::Read),
            0x9 => Some(Self::Write),
            0xA => Some(Self::Lock),
            0xB => Some(Self::IoCtl),
            0xC => Some(Self::Cancel),
            0xD => Some(Self::Echo),
            0xE => Some(Self::QueryDirectory),
            0xF => Some(Self::ChangeNotify),
            0x10 => Some(Self::QueryInfo),
            0x11 => Some(Self::SetInfo),
            0x12 => Some(Self::OplockBreak),
            _ => None,
        }
    }
}
