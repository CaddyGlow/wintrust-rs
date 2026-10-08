fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            wintrust_fuzz::catalog(data);
        });
    }
}
