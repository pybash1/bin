use std::ops::Deref;
use actix_web::{
    FromRequest, HttpRequest, HttpMessage, dev::Payload,
    http::header::{self, HeaderValue},
};
use futures::future::ready;

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
        let is_plaintext = req.content_type() == "text/plain" || 
            req.headers()
                .get(header::USER_AGENT)
                .and_then(|u| u.to_str().ok())
                .and_then(|s| s.split('/').next())
                .is_none_or(|agent| matches!(agent, "Wget" | "curl" | "HTTPie"));
        
        ready(Ok(IsPlaintextRequest(is_plaintext)))
    }
}

pub struct HostHeader(pub Option<HeaderValue>);

impl FromRequest for HostHeader {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Ok(Self(req.headers().get(header::HOST).cloned())))
    }
}

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
                code.len() == 8 && 
                code.chars().all(|c| c.is_ascii_alphanumeric() && (c.is_ascii_uppercase() || c.is_ascii_digit()))
            })
            .map(String::from);
        
        ready(Ok(Self(device_code)))
    }
}
