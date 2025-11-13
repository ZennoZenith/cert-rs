use std::{fmt, ops::Deref, str::FromStr};

use chrono::Duration;
#[cfg(feature = "sqlx")]
use chrono::{DateTime, Utc};

// region:    --- Error

#[derive(thiserror::Error, Debug)]
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
pub struct FailToParse(String);

impl fmt::Display for FailToParse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(thiserror::Error, Debug)]
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
pub struct TimeOutOrRange(String);

impl fmt::Display for TimeOutOrRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// endregion: --- Error

#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[cfg(feature = "sqlx")]
#[derive(sqlx::Type)]
#[sqlx(transparent)]
#[cfg(feature = "serde")]
pub struct TimeRfc3339(DateTime<Utc>);

impl TimeRfc3339 {
    pub fn inner(&self) -> DateTime<Utc> {
        self.0
    }

    pub fn now_utc() -> Self {
        Self(Utc::now())
    }

    pub fn parse_utc(moment: &str) -> std::result::Result<Self, FailToParse> {
        DateTime::parse_from_rfc3339(moment)
            .map(|v| Self(v.to_utc()))
            .map_err(|_| FailToParse(moment.to_string()))
    }

    pub fn format_time(&self) -> String {
        self.0.to_rfc3339()
    }

    pub fn now_utc_plus_sec_str(
        time_delta: Duration,
    ) -> std::result::Result<String, TimeOutOrRange> {
        let new_time = Self::now_utc().0.checked_add_signed(time_delta).ok_or(
            TimeOutOrRange(format!(
                "{} + {}msec",
                Self::now_utc().0,
                time_delta.num_milliseconds()
            )),
        )?;
        Ok(Self(new_time).format_time())
    }
}

impl Deref for TimeRfc3339 {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for TimeRfc3339 {
    type Err = FailToParse;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse_utc(value)
    }
}

impl TryFrom<&str> for TimeRfc3339 {
    type Error = FailToParse;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::parse_utc(value)
    }
}

impl From<DateTime<Utc>> for TimeRfc3339 {
    fn from(value: DateTime<Utc>) -> Self {
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
            Ok(v) => v.map_err(|v| {
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
