#[derive(thiserror::Error, Debug)]
pub enum RSTError {
    #[error("Error making a request {0:?}")]
    Request(#[from] reqwest::Error),
    #[error("Error serializing request {0:?}")]
    Serialization(#[from] quick_xml::SeError),
    #[error("Error deserializing response {0:?}")]
    Deserialization(#[from] quick_xml::DeError),
    #[error("Unable to decode base64")]
    Base64(#[from] base64::DecodeError),
    #[error("Error processing XML for verification {0:?}")]
    Bergshamra(#[from] bergshamra::Error),
    #[error("Error building RST request {0:?}")]
    Builder(#[from] RSTBuilderError),

    #[error("Microsoft rejected the stored device credential")]
    DeviceCredentialRejected { status: Option<u32> },
    #[error("Stored device credentials are unavailable")]
    DeviceCredentialUnavailable,
    #[error("The device credential could not be renewed; try again or sign in")]
    DeviceCredentialRefreshFailed,
    #[error("Stored device signing data is invalid")]
    InvalidDeviceCredential,
    #[error("Microsoft returned no device token")]
    EmptyDeviceTokenResponse,
    #[error("Microsoft returned an unsupported device-token response")]
    UnexpectedDeviceTokenResponse,

    #[error("Response is malformed, unable to find nonce for decryption")]
    MissingNonce,
    #[error("Unexpected error deriving hmac key")]
    HmacKey,
    #[error("The signature verification failed - {0}")]
    InvalidResponseSignature(String),
}

#[derive(thiserror::Error, Debug)]
pub enum RSTBuilderError {
    #[error("Error serializing request")]
    Serialization(#[from] quick_xml::SeError),
    #[error("Error derializing token data")]
    Deserialization(#[from] quick_xml::DeError),
    #[error("Error processing XML for signing {0:?}")]
    Bergshamra(#[from] bergshamra::Error),
    #[error("Builder was provided with invalid set of tokens")]
    UnsupportedTokenCombination,
}
