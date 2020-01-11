use failure::Fail;

pub type Result<T, E = failure::Error> = std::result::Result<T, E>;

#[derive(Debug, Fail)]
pub enum InitError {
    #[fail(display = "no routes were specified")]
    NoRoutes,
}

#[derive(Debug, Fail)]
pub enum ReadError {
    #[fail(display = "an invalid var int was supplied")]
    VarInt,

    #[fail(display = "too long string was provided")]
    LongStringLength,

    #[fail(display = "too short string was provided")]
    ShortStringLength,

    #[fail(display = "an illformed legacy ping was provided")]
    InvalidLegacyPing,

    #[fail(display = "encoding_rs error: {}", _0)]
    EncodingError(String),
}

pub trait ToFailure {
    fn failure(self) -> failure::Error;
}

impl<F: Fail> ToFailure for F {
    fn failure(self) -> failure::Error {
        self.into()
    }
}
