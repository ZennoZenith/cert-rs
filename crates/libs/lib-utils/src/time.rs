use std::ops::Deref;

use time::{Duration, OffsetDateTime};

pub use time::format_description::well_known::Rfc3339;

// region:    --- Error

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug, strum_macros::Display)]
pub enum Error {
    FailToDateParse(String),
}

// endregion: --- Error

#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[cfg(feature = "sqlx")]
#[derive(sqlx::Type)]
#[sqlx(transparent)]
pub struct TimeRfc3339(OffsetDateTime);

impl TimeRfc3339 {
    pub fn inner(&self) -> OffsetDateTime {
        self.0
    }

    pub fn now_utc() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    pub fn parse_utc(moment: &str) -> Result<OffsetDateTime> {
        OffsetDateTime::parse(moment, &Rfc3339)
            .map_err(|_| Error::FailToDateParse(moment.to_string()))
    }

    pub fn format_time(&self) -> String {
        self.0.format(&Rfc3339).unwrap() // TODO: need to check if safe.
    }

    pub fn now_utc_plus_sec_str(sec: f64) -> String {
        let new_time = Self::now_utc().0 + Duration::seconds_f64(sec);
        Self(new_time).format_time()
    }
}

impl Deref for TimeRfc3339 {
    type Target = OffsetDateTime;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&str> for TimeRfc3339 {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        OffsetDateTime::parse(value, &Rfc3339)
            .map(Self)
            .map_err(|_| Error::FailToDateParse(value.to_string()))
    }
}

impl From<OffsetDateTime> for TimeRfc3339 {
    fn from(value: OffsetDateTime) -> Self {
        Self(value)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::de::Deserialize<'de> for TimeRfc3339 {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<TimeRfc3339, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let temp =
            String::deserialize(deserializer).map(|v| Self::parse_utc(&v));

        match temp {
            Ok(v) => v.map(Self).map_err(|v| {
                serde::de::Error::custom(format!(
                    "Invalid Rfc3339 time format: {v}",
                ))
            }),
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TimeRfc3339 {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.format_time();
        serializer.serialize_str(&s)
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    pub type Result<T> = std::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For tests.

    use super::*;

    #[test]
    fn vaild_rfc3339_string() -> Result<()> {
        // -- Setup & Fixtures
        const TIME: &str = "2020-09-08T13:10:08.511Z";

        // -- Exec
        let _ = TimeRfc3339::try_from(TIME).unwrap();

        // -- Check

        Ok(())
    }
}
// endregion: --- Tests
