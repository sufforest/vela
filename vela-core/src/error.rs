#[derive(Debug, thiserror::Error)]
pub enum VelaError {
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unknown: {0}")]
    Unknown(String),
    #[error("bad json: {0}")]
    BadJson(String),
    /// Body is not parseable as JSON at all (invalid syntax, non-UTF-8
    /// bytes, etc.). Distinct from `BadJson`, which is "valid JSON,
    /// wrong shape." Spec maps to `M_NOT_JSON` (status 400).
    #[error("not json: {0}")]
    NotJson(String),
    #[error("username already taken")]
    UserInUse,
    #[error("invalid username")]
    InvalidUsername,
    #[error("unknown or missing token")]
    UnknownToken,
    #[error("missing access token")]
    MissingToken,
    #[error("user account has been deactivated")]
    UserDeactivated,
    #[error("bad alias: {0}")]
    BadAlias(String),
    /// Spec: `M_INVALID_PARAM` (status 400). A request parameter is
    /// well-formed JSON but fails domain validation (e.g. an alias string
    /// that doesn't match the `#localpart:server` grammar).
    #[error("invalid param: {0}")]
    InvalidParam(String),
    /// Spec: status 413 (`M_TOO_LARGE`) when a built event's canonical
    /// JSON exceeds the 65,536-byte limit. Surfaced from send paths
    /// after the event is fully assembled.
    #[error("event too large: {0}")]
    EventTooLarge(String),
    #[error("unsupported room version: {0}")]
    UnsupportedRoomVersion(String),
    #[error("store error: {0}")]
    Store(String),
    /// Pass-through for User-Interactive Authentication responses where the
    /// body is built by the UIA module. The handler returns this so
    /// `ApiError::into_response` can surface the prebuilt JSON verbatim.
    #[error("uia: status={status}")]
    Uia { status: u16, body: String },
    /// Carries a status / errcode / message verbatim. Used by handlers
    /// returning Matrix-extension errcodes (e.g. MSC4306's
    /// `IO.ELEMENT.MSC4306.M_NOT_IN_THREAD`) that don't fit the
    /// standard Vela-wide error vocabulary.
    #[error("{msg}")]
    Custom {
        status: u16,
        errcode: &'static str,
        msg: String,
    },
}

impl VelaError {
    pub fn errcode(&self) -> &'static str {
        match self {
            Self::Forbidden(_) => "M_FORBIDDEN",
            Self::NotFound(_) => "M_NOT_FOUND",
            Self::Unknown(_) => "M_UNKNOWN",
            Self::BadJson(_) => "M_BAD_JSON",
            Self::NotJson(_) => "M_NOT_JSON",
            Self::UserInUse => "M_USER_IN_USE",
            Self::InvalidUsername => "M_INVALID_USERNAME",
            Self::UnknownToken => "M_UNKNOWN_TOKEN",
            Self::MissingToken => "M_MISSING_TOKEN",
            Self::UserDeactivated => "M_USER_DEACTIVATED",
            Self::BadAlias(_) => "M_BAD_ALIAS",
            Self::InvalidParam(_) => "M_INVALID_PARAM",
            Self::EventTooLarge(_) => "M_TOO_LARGE",
            Self::UnsupportedRoomVersion(_) => "M_UNSUPPORTED_ROOM_VERSION",
            Self::Store(_) => "M_UNKNOWN",
            Self::Uia { .. } => "M_FORBIDDEN",
            Self::Custom { errcode, .. } => errcode,
        }
    }

    pub fn status_code(&self) -> u16 {
        match self {
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::EventTooLarge(_) => 413,
            Self::UnknownToken | Self::MissingToken => 401,
            Self::UserInUse
            | Self::InvalidUsername
            | Self::BadJson(_)
            | Self::NotJson(_)
            | Self::BadAlias(_)
            | Self::InvalidParam(_)
            | Self::UnsupportedRoomVersion(_) => 400,
            // Note: EventTooLarge is handled above (413).
            Self::UserDeactivated => 403,
            Self::Uia { status, .. } => *status,
            Self::Custom { status, .. } => *status,
            Self::Unknown(_) | Self::Store(_) => 500,
        }
    }
}
