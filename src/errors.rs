use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use std::fmt::{self, Formatter};

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
    status: u16,
}

macro_rules! error_type {
    ($name:ident, $message:expr, $status:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl ResponseError for $name {
            fn error_response(&self) -> HttpResponse {
                HttpResponse::build($status).json(ErrorResponse {
                    error: $message,
                    status: $status.as_u16(),
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", $message)
            }
        }
    };
}

error_type!(NotFound, "Not Found", StatusCode::NOT_FOUND);
error_type!(Unauthorized, "Unauthorized", StatusCode::UNAUTHORIZED);
error_type!(BadRequest, "Bad Request", StatusCode::BAD_REQUEST);

