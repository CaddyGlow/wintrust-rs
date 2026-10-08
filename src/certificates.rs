//! Borrowed DER artifact collections.
use alloc::vec::Vec;

/// A collection view over owned or borrowed DER buffers, without copying bytes.
#[derive(Debug, Clone, Copy)]
pub struct CertificateStore<'a>(Storage<'a>);
#[derive(Debug, Clone, Copy)]
enum Storage<'a> {
    Owned(&'a [Vec<u8>]),
    Borrowed(&'a [&'a [u8]]),
}
impl Default for CertificateStore<'_> {
    fn default() -> Self {
        Self(Storage::Borrowed(&[]))
    }
}
impl<'a> CertificateStore<'a> {
    pub const fn from_owned(buffers: &'a [Vec<u8>]) -> Self {
        Self(Storage::Owned(buffers))
    }
    pub const fn from_slices(buffers: &'a [&'a [u8]]) -> Self {
        Self(Storage::Borrowed(buffers))
    }
    pub fn len(self) -> usize {
        match self.0 {
            Storage::Owned(buffers) => buffers.len(),
            Storage::Borrowed(buffers) => buffers.len(),
        }
    }
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
    pub fn get(self, index: usize) -> Option<&'a [u8]> {
        match self.0 {
            Storage::Owned(buffers) => buffers.get(index).map(Vec::as_slice),
            Storage::Borrowed(buffers) => buffers.get(index).copied(),
        }
    }
    pub fn iter(self) -> impl ExactSizeIterator<Item = &'a [u8]> {
        (0..self.len()).map(move |index| match self.0 {
            Storage::Owned(buffers) => buffers[index].as_slice(),
            Storage::Borrowed(buffers) => buffers[index],
        })
    }
}
impl<'a> From<&'a [Vec<u8>]> for CertificateStore<'a> {
    fn from(value: &'a [Vec<u8>]) -> Self {
        Self::from_owned(value)
    }
}
impl<'a> From<&'a Vec<Vec<u8>>> for CertificateStore<'a> {
    fn from(value: &'a Vec<Vec<u8>>) -> Self {
        Self::from_owned(value)
    }
}
impl<'a, const N: usize> From<&'a [Vec<u8>; N]> for CertificateStore<'a> {
    fn from(value: &'a [Vec<u8>; N]) -> Self {
        Self::from_owned(value)
    }
}
impl<'a> From<&'a [&'a [u8]]> for CertificateStore<'a> {
    fn from(value: &'a [&'a [u8]]) -> Self {
        Self::from_slices(value)
    }
}
impl<'a, const N: usize> From<&'a [&'a [u8]; N]> for CertificateStore<'a> {
    fn from(value: &'a [&'a [u8]; N]) -> Self {
        Self::from_slices(value)
    }
}
impl<'a> From<&'a Vec<&'a [u8]>> for CertificateStore<'a> {
    fn from(value: &'a Vec<&'a [u8]>) -> Self {
        Self::from_slices(value)
    }
}
