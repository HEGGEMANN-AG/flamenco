use std::io::{Read, Write};

pub trait LittleEndian: Copy {
    fn write_le<W: Write>(self, w: W) -> Result<(), std::io::Error>;
    fn read_le<R: Read>(r: R) -> Result<Self, std::io::Error>;
}

macro_rules! impl_le {
    ($($t:ty,)*) => {
        $(
            impl LittleEndian for $t {
                fn write_le<W: Write>(self, mut w: W) -> Result<(), std::io::Error> {
                    w.write_all(&self.to_le_bytes())?;
                    Ok(())
                }
                fn read_le<R: Read>(mut r: R) -> Result<Self, std::io::Error> {
                    let mut c: [u8; size_of::<$t>()] = Default::default();
                    r.read_exact(&mut c)?;
                    Ok(<$t>::from_le_bytes(c))
                }
            }
        )*
    };
}

impl_le!(u16, u32, u64, u128,);
