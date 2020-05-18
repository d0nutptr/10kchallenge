use serde::{Serialize, Deserialize};
use crate::Participant;

#[derive(Serialize, Deserialize)]
pub struct ChallengeInitiateRequest {
    pub participant: Participant,
    pub proxy_config: String,
}