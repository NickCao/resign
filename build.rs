fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile(&["proto/resign.proto", "proto/sequoia.proto"], &["proto"])?;
    Ok(())
}
