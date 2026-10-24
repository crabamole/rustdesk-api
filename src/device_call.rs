//! `SignedDevice<T>`: the body of a call a device signs with its key
//! (rustdesk docs/design-signed-device-calls.md).
use rocket::data::{Data, FromData, Limits, Outcome};
use rocket::http::Status;
use rocket::Request;
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::RequestBody;
use rocket_okapi::request::OpenApiFromData;
use rocket_okapi::{JsonSchema, Result as OkapiResult};
use serde::de::DeserializeOwned;
use state::{device_call, ApiState};

/// The device a call names.
pub trait DeviceCall {
    fn device(&self) -> (&str, &str);

    /// Calls a viewer sends, which carry no device signature.
    fn from_viewer(&self) -> bool {
        false
    }
}

impl DeviceCall for utils::HeartbeatRequest {
    fn device(&self) -> (&str, &str) {
        (&self.id, &self.uuid)
    }
}

impl DeviceCall for utils::SystemInfo {
    fn device(&self) -> (&str, &str) {
        (self.id.as_deref().unwrap_or_default(), self.uuid.as_deref().unwrap_or_default())
    }
}

impl DeviceCall for utils::AuditConnRequest {
    fn device(&self) -> (&str, &str) {
        (&self.id, &self.uuid)
    }

    /// A viewer's session menu note (spec §4), as `state::audit_conn` recognises it; it only lands
    /// on an existing row of its session.
    fn from_viewer(&self) -> bool {
        self.action.is_empty() && self.note.is_some() && self.uuid.is_empty() && self.peer.is_none() && self.conn_type.is_none()
    }
}

impl DeviceCall for utils::AuditFileRequest {
    fn device(&self) -> (&str, &str) {
        (&self.id, &self.uuid)
    }
}

impl DeviceCall for utils::AuditClipboardRequest {
    fn device(&self) -> (&str, &str) {
        (&self.id, &self.uuid)
    }
}

impl DeviceCall for utils::AuditAlarmRequest {
    fn device(&self) -> (&str, &str) {
        (&self.id, &self.uuid)
    }
}

/// A JSON body accepted only with a valid `X-Device-Signature` of the device it names: 422 for a
/// malformed body, 401 for a missing or wrong signature. Viewer calls (`from_viewer`) need none.
pub struct SignedDevice<T>(pub T);

impl<T> std::ops::Deref for SignedDevice<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for SignedDevice<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[rocket::async_trait]
impl<'r, T: DeserializeOwned + DeviceCall + Send> FromData<'r> for SignedDevice<T> {
    type Error = String;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        let limit = req.limits().get("json").unwrap_or(Limits::JSON);
        let body = match data.open(limit).into_bytes().await {
            Ok(b) if b.is_complete() => b.into_inner(),
            Ok(_) => return Outcome::Error((Status::PayloadTooLarge, "data limit exceeded".into())),
            Err(e) => return Outcome::Error((Status::BadRequest, e.to_string())),
        };
        let value: T = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) if e.classify() == serde_json::error::Category::Data => {
                return Outcome::Error((Status::UnprocessableEntity, e.to_string()))
            }
            Err(e) => return Outcome::Error((Status::BadRequest, e.to_string())),
        };
        if value.from_viewer() {
            return Outcome::Success(SignedDevice(value));
        }
        let header = req.headers().get_one(device_call::HEADER).unwrap_or_default();
        let (id, uuid) = value.device();
        let pk = match req.rocket().state::<ApiState>() {
            Some(state) => state.device_pk(id, uuid).await,
            None => None,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        if pk.is_some_and(|pk| device_call::verify(&pk, header, req.uri().path().as_str(), &body, now)) {
            Outcome::Success(SignedDevice(value))
        } else {
            // Debug only: devices call at their own rate; the access log already records the 401.
            log::debug!("{}: refused an unsigned or wrongly signed call for device {id:?}", req.uri().path());
            Outcome::Error((Status::Unauthorized, "device signature required".into()))
        }
    }
}

impl<'r, T: JsonSchema + DeserializeOwned + DeviceCall + Send> OpenApiFromData<'r> for SignedDevice<T> {
    fn request_body(gen: &mut OpenApiGenerator) -> OkapiResult<RequestBody> {
        use rocket_okapi::okapi::{openapi3::MediaType, Map};
        let mut content = Map::new();
        content.insert("application/json".to_owned(), MediaType { schema: Some(gen.json_schema::<T>()), ..MediaType::default() });
        Ok(RequestBody { content, required: true, ..RequestBody::default() })
    }
}
