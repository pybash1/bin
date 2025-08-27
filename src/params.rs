use std::ops::Deref;

use actix_web::{
    FromRequest, HttpMessage, HttpRequest,
    dev::Payload,
    http::header::{self, HeaderValue},
};
use futures::future::ok;

/// Holds a value that determines whether or not this request wanted a plaintext response.
///
/// We assume anything with the text/plain Accept or Content-Type headers want plaintext,
/// and also anything calling us from the console or that we can't identify.
pub struct IsPlaintextRequest(pub bool);

impl Deref for IsPlaintextRequest {
    type Target = bool;

    fn deref(&self) -> &bool {
        &self.0
    }
}

impl FromRequest for IsPlaintextRequest {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        if req.content_type() == "text/plain" {
            return ok(IsPlaintextRequest(true));
        }

        match req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|u| u.to_str().unwrap().split('/').next())
        {
            None | Some("Wget" | "curl" | "HTTPie") => ok(IsPlaintextRequest(true)),
            _ => ok(IsPlaintextRequest(false)),
        }
    }
}

/// Gets the Host header from the request.
///
/// The inner value of this `HostHeader` will be `None` if there was no Host header
/// on the request.
pub struct HostHeader(pub Option<HeaderValue>);

impl FromRequest for HostHeader {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ok(Self(req.headers().get(header::HOST).cloned()))
    }
}

/// Gets the Device-Code header from the request.
///
/// The inner value will be `None` if there was no Device-Code header or if it's invalid.
/// Valid device codes are 8 character alphanumeric (A-Z, 0-9) strings.
pub struct DeviceCode(pub Option<String>);

impl FromRequest for DeviceCode {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let device_code = req
            .headers()
            .get("Device-Code")
            .and_then(|h| h.to_str().ok())
            .filter(|code| {
                code.len() == 8 && code.chars().all(|c| c.is_ascii_alphanumeric() && (c.is_ascii_uppercase() || c.is_ascii_digit()))
            })
            .map(String::from);
        
        ok(Self(device_code))
    }
}
