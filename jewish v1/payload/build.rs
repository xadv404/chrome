fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=oleaut32");
    }
}
