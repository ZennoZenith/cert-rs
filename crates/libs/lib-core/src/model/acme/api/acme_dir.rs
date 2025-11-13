use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    pub new_nonce: Url,
    pub new_account: Url,
    pub new_order: Url,
    pub revoke_cert: Url,
    pub key_change: Url,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_authz: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<AcmeDirectoryMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectoryMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa_identities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_required: Option<bool>,
}
