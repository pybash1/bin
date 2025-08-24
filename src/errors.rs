use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use std::fmt::Formatter;

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    status: u16,
}

macro_rules! impl_response_error_for_json {
    ($ty:ty, $message:expr, $status:expr) => {
        impl ResponseError for $ty {
            fn error_response(&self) -> HttpResponse {
                let error_response = ErrorResponse {
                    error: $message.to_string(),
                    status: $status.as_u16(),
                };
                HttpResponse::build($status).json(error_response)
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", $message)
            }
        }
    };
}

#[derive(Debug)]
pub struct NotFound;

impl_response_error_for_json!(NotFound, "Not Found", StatusCode::NOT_FOUND);

#[derive(Debug)]
#[allow(dead_code)]
pub struct InternalServerError(pub Box<dyn std::error::Error>);

impl_response_error_for_json!(
    InternalServerError,
    "Internal Server Error",
    StatusCode::INTERNAL_SERVER_ERROR
);

#[derive(Debug)]
pub struct Unauthorized;

impl_response_error_for_json!(Unauthorized, "Unauthorized", StatusCode::UNAUTHORIZED);

