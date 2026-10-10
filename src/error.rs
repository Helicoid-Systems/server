//! Shared error type for the HS server foundation.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// Stable machine-readable error codes for contract version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unprocessable,
    RateLimited,
    NotImplemented,
    SecurityStateUnavailable,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Unprocessable => "unprocessable",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::NotImplemented => "not_implemented",
            ErrorCode::SecurityStateUnavailable => "security_state_unavailable",
            ErrorCode::Internal => "internal",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::Unprocessable => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            ErrorCode::SecurityStateUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{message}")]
    Api {
        code: ErrorCode,
        message: String,
        /// Optional field-level detail that is safe to return to the caller.
        detail: Option<String>,
    },
    #[error("storage failure")]
    Storage(#[from] rusqlite::Error),
    #[error("password hash failure")]
    PasswordHash(String),
    #[error("secure randomness failure")]
    Random(String),
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::BadRequest,
            message: message.into(),
            detail: None,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::Unauthorized,
            message: message.into(),
            detail: None,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::Forbidden,
            message: message.into(),
            detail: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::NotFound,
            message: message.into(),
            detail: None,
        }
    }

    pub fn conflict(message: impl Into<String>, detail: Option<String>) -> Self {
        AppError::Api {
            code: ErrorCode::Conflict,
            message: message.into(),
            detail,
        }
    }

    pub fn unprocessable(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::Unprocessable,
            message: message.into(),
            detail: None,
        }
    }

    pub fn rate_limited(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::RateLimited,
            message: message.into(),
            detail: None,
        }
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::NotImplemented,
            message: message.into(),
            detail: None,
        }
    }

    pub fn security_state_unavailable(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::SecurityStateUnavailable,
            message: message.into(),
            detail: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        AppError::Api {
            code: ErrorCode::Internal,
            message: message.into(),
            detail: None,
        }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            AppError::Api { code, .. } => *code,
            AppError::Storage(_) => ErrorCode::Internal,
            AppError::PasswordHash(_) => ErrorCode::Internal,
            AppError::Random(_) => ErrorCode::Internal,
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorPayload,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.code();
        // Storage/password/random failures are logged without request secrets.
        let (message, detail) = match &self {
            AppError::Api {
                message, detail, ..
            } => (message.clone(), detail.clone()),
            AppError::Storage(err) => {
                tracing::error!(error = %err, "storage operation failed");
                (
                    "required storage operation failed".to_string(),
                    Some("security_state_check".to_string()),
                )
            }
            AppError::PasswordHash(err) => {
                tracing::error!(error = %err, "password hashing failed");
                ("credential processing failed".to_string(), None)
            }
            AppError::Random(err) => {
                tracing::error!(error = %err, "secure randomness failed");
                ("secure randomness failed".to_string(), None)
            }
        };
        let body = ErrorBody {
            error: ErrorPayload {
                code: code.as_str(),
                message,
                detail,
            },
        };
        (code.status(), Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
