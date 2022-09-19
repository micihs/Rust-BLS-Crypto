use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("size mismatch")]
    SizeMismatch,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("group decode error")]
    GroupDecode,
    #[error("curve decode error")]
    CurveDecode,
    #[error("prime field decode error")]
    FieldDecode,
    #[error("invalid Private Key")]
    InvalidPrivateKey,
    #[error("zero sized input")]
    ZeroSizedInput,
}