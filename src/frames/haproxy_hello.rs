use crate::{
    SpopFrame,
    frame::{FramePayload, FrameType, Metadata},
    frames::capabilities::FrameCapabilities,
    types::TypedData,
};
use std::{collections::HashMap, convert::TryFrom, str::FromStr};

// 3.2.4. Frame: HAPROXY-HELLO
// ----------------------------
//
// This frame is the first one exchanged between HAProxy and an agent, when the
// connection is established. The payload of this frame is a KV-LIST. STREAM-ID
// and FRAME-ID are must be set 0.
//
// Following items are mandatory in the KV-LIST:
//
//   * "supported-versions"    <STRING>
//
//     Last SPOP major versions supported by HAProxy. It is a comma-separated list
//     of versions, following the format "Major.Minor". Spaces must be ignored, if
//     any. When a major version is announced by HAProxy, it means it also support
//     all previous minor versions.
//
//     Example: "2.0, 1.5" means HAProxy supports SPOP 2.0 and 1.0 to 1.5
//
//   * "max-frame-size"    <UINT32>
//
//     This is the maximum size allowed for a frame. The HAPROXY-HELLO frame must
//     be lower or equal to this value.
//
//   * "capabilities"    <STRING>
//
//     This a comma-separated list of capabilities supported by HAProxy. Spaces
//     must be ignored, if any.
//
// Following optional items can be added in the KV-LIST:
//
//   * "healthcheck"    <BOOLEAN>
//
//     If this item is set to TRUE, then the HAPROXY-HELLO frame is sent during a
//     SPOE health check. When set to FALSE, this item can be ignored.
//
//   * "engine-id"    <STRING>
//
//     This is a uniq string that identify a SPOE engine.
//
// To finish the HELLO handshake, the agent must return an AGENT-HELLO frame with
// its supported SPOP version, the lower value between its maximum size allowed
// for a frame and the HAProxy one and capabilities it supports. If an error
// occurs or if an incompatibility is detected with the agent configuration, an
// AGENT-DISCONNECT frame must be returned.
#[derive(Debug)]
pub struct HaproxyHello {
    pub supported_versions: Vec<String>,
    pub max_frame_size: u32,
    pub capabilities: Vec<FrameCapabilities>,
    pub healthcheck: Option<bool>,
    pub engine_id: Option<String>,
}

impl HaproxyHello {
    pub fn to_kv_list(&self) -> HashMap<String, TypedData> {
        let mut map = HashMap::new();

        map.insert(
            "supported-versions".to_string(),
            TypedData::String(self.supported_versions.join(",")),
        );

        map.insert(
            "max-frame-size".to_string(),
            TypedData::UInt32(self.max_frame_size),
        );

        let caps_string = self
            .capabilities
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        map.insert("capabilities".into(), TypedData::String(caps_string));

        if let Some(healthcheck) = self.healthcheck {
            map.insert("healthcheck".to_string(), TypedData::Bool(healthcheck));
        }

        if let Some(ref engine_id) = self.engine_id {
            map.insert(
                "engine-id".to_string(),
                TypedData::String(engine_id.clone()),
            );
        }

        map
    }
}

#[derive(Debug)]
pub struct HaproxyHelloFrame {
    pub metadata: Metadata,
    pub payload: HaproxyHello,
}

impl SpopFrame for HaproxyHelloFrame {
    fn frame_type(&self) -> &FrameType {
        &FrameType::HaproxyHello
    }

    fn metadata(&self) -> Metadata {
        self.metadata.clone()
    }

    fn payload(&self) -> FramePayload {
        FramePayload::KVList(self.payload.to_kv_list())
    }
}

impl TryFrom<FramePayload> for HaproxyHello {
    type Error = String;

    fn try_from(payload: FramePayload) -> Result<Self, Self::Error> {
        // Ensure that the payload is a KVList
        if let FramePayload::KVList(kv_list) = payload {
            let supported_versions = kv_list
                .get("supported-versions")
                .and_then(|v| match v {
                    TypedData::String(v) => Some(
                        v.split(',')
                            .map(|s| s.trim().to_string())
                            .collect::<Vec<_>>(),
                    ),
                    _ => None,
                })
                .ok_or_else(|| "Missing or invalid supported_versions".to_string())?;

            let max_frame_size = kv_list
                .get("max-frame-size")
                .and_then(|v| match v {
                    TypedData::UInt32(val) => Some(*val),
                    _ => None,
                })
                .ok_or_else(|| "Missing or invalid max_frame_size".to_string())?;

            let capabilities = kv_list
                .get("capabilities")
                .and_then(|v| match v {
                    TypedData::String(v) => Some(
                        v.split(',')
                            .map(|s| s.trim())
                            .filter_map(|s| FrameCapabilities::from_str(s).ok())
                            .collect::<Vec<FrameCapabilities>>(),
                    ),
                    _ => None,
                })
                .ok_or_else(|| "Missing or invalid capabilities".to_string())?;

            let healthcheck = kv_list.get("healthcheck").and_then(|v| {
                if let TypedData::Bool(val) = v {
                    Some(*val)
                } else {
                    None
                }
            });

            let engine_id = kv_list.get("engine-id").and_then(|v| {
                if let TypedData::String(val) = v {
                    Some(val.clone())
                } else {
                    None
                }
            });

            Ok(Self {
                supported_versions,
                max_frame_size,
                capabilities,
                healthcheck,
                engine_id,
            })
        } else {
            Err("Invalid FramePayload type, expected KVList.".to_string())
        }
    }
}
