use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use strongbox_proto::{ApiError, ErrorCode, NodeVersion};

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: ErrorCode,
    pub message: String,
    pub conflicts: Vec<NodeVersion>,
}

impl AppError {
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        AppError {
            status,
            code,
            message: message.into(),
            conflicts: Vec::new(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "authentication required",
        )
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, "not found")
    }

    pub fn conflict(conflicts: Vec<NodeVersion>) -> Self {
        AppError {
            conflicts,
            ..Self::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "version conflict",
            )
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ApiError {
            code: self.code,
            message: self.message,
            conflicts: self.conflicts,
        };
        (self.status, Json(body)).into_response()
    }
}

// Raw error text can carry identifiers (constraint values, blob paths that embed the account
// and blob id), so outside debug mode only a coarse category is logged.

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        if crate::debug_logging() {
            tracing::error!("database error: {e}");
        } else {
            let kind = match &e {
                sqlx::Error::Database(_) => "constraint or query",
                sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => "connection pool",
                sqlx::Error::Io(_) => "i/o",
                _ => "other",
            };
            tracing::error!("database error ({kind})");
        }
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            "internal error",
        )
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        if crate::debug_logging() {
            tracing::error!("storage error: {e}");
        } else {
            tracing::error!("storage error ({:?})", e.kind());
        }
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            "internal error",
        )
    }
}

pub type AppResult<T> = Result<T, AppError>;
