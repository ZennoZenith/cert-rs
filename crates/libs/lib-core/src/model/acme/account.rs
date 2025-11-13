use std::{ops::Deref, str::FromStr};

use lib_utils::time::TimeRfc3339;

use color_eyre::Result;
use serde::Serialize;
use sqlx::prelude::FromRow;
use url::Url;

use crate::{
    ctx::Ctx,
    model::{ModelManager, acme::api::AccountCert, store::dbx},
};

#[derive(
    Debug,
    Clone,
    Serialize,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::IntoStaticStr,
    PartialEq,
    Eq,
)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
pub enum KeyType {
    #[default]
    #[serde(rename = "RSA")]
    Rsa,
}

impl From<String> for KeyType {
    fn from(value: String) -> Self {
        Self::from_str(&value).unwrap_or_default()
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for KeyType
where
    // we want to delegate some of the work to string decoding so let's make sure strings
    // are supported by the database
    &'r str: sqlx::Decode<'r, sqlx::Sqlite>,
{
    fn decode(
        value: <sqlx::Sqlite as sqlx::Database>::ValueRef<'r>,
    ) -> std::result::Result<
        KeyType,
        Box<dyn std::error::Error + 'static + Send + Sync>,
    > {
        // the interface of ValueRef is largely unstable at the moment
        // so this is not directly implementable

        // however, you can delegate to a type that matches the format of the type you want
        // to decode (such as a UTF-8 string)

        let value = <&str as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;

        // now you can parse this into your type (assuming there is a `FromStr`)

        Ok(match KeyType::from_str(value) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!("Invalid Key type: {value}");
                Self::default()
            }
        })
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Sqlite> for KeyType {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> std::result::Result<sqlx::encode::IsNull, sqlx::error::BoxDynError>
    {
        let s: &'static str = self.into();
        <&'q str as sqlx::Encode<sqlx::Sqlite>>::encode(s, buf)
    }
}

#[derive(Debug, sqlx::Type)]
#[sqlx(transparent)]
pub struct AccountId(Box<str>);

impl From<String> for AccountId {
    fn from(value: String) -> Self {
        Self(Box::from(value))
    }
}

impl AccountId {
    pub fn new(account_id: Url) -> Self {
        Self(Box::from(account_id.as_str()))
    }
}

impl Deref for AccountId {
    type Target = Box<str>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, FromRow)]
pub struct AcmeAccount {
    pub serial_id: i64,
    pub account_id: AccountId,
    pub private_key_pem: Vec<u8>,
    pub public_key_pem: Vec<u8>,
    pub domain_key_pem: Vec<u8>,
    pub key_type: KeyType,
    pub mtime: String,
    pub ctime: String,
}

pub struct AcmeAccountBmc;

impl AcmeAccountBmc {
    pub async fn create(
        _ctx: &Ctx,
        mm: &ModelManager,
        account_c: (AccountId, AccountCert),
    ) -> Result<i64> {
        let (account_id, account_cert) = account_c;

        let private_key_pem = account_cert.private_key.private_key_to_pem()?;
        let public_key_pem = account_cert.public_key.public_key_to_pem()?;
        let domain_key_pem = account_cert.domain_key.private_key_to_pem()?;

        // Start the transaction
        let mm = mm.new_with_txn();

        mm.dbx().begin_txn().await?;

        let now = TimeRfc3339::now_utc().format_time();

        let key_type: &'static str = account_cert.key_type.into();

        let sqlx_query = sqlx::query!(
            "INSERT INTO acme_account (account_id, private_key_pem, public_key_pem, domain_key_pem, key_type, ctime, mtime) 
                VALUES (?, ?, ?, ?, ?, ?, ?) 
            RETURNING serial_id;",
            account_id,
            private_key_pem,
            public_key_pem,
            domain_key_pem,
            key_type,
            now,
            now,
        )
        .fetch_one(mm.dbx().db())
        .await
        .map_err(dbx::Error::from)?;

        let serial_id = sqlx_query.serial_id;

        // Commit the transaction
        mm.dbx().commit_txn().await?;

        Ok(serial_id)
    }

    pub async fn get_first(
        _ctx: &Ctx,
        mm: &ModelManager,
    ) -> Result<AcmeAccount> {
        let user = sqlx::query_as!(
            AcmeAccount,
            r#"SELECT serial_id, account_id, private_key_pem,
            public_key_pem, domain_key_pem, key_type, ctime, mtime
            FROM acme_account 
            ORDER BY serial_id 
            LIMIT 1;"#,
        )
        .fetch_one(mm.dbx().db())
        .await
        .map_err(dbx::Error::from)?;

        Ok(user)
    }
}
