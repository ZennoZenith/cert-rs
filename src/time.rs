use std::{fmt, ops::Deref, str::FromStr};

use chrono::Duration;
use chrono::{DateTime, Utc};

// region:    --- Error

#[derive(thiserror::Error, Debug, serde::Serialize)]
pub struct FailToParse(String);

impl fmt::Display for FailToParse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(thiserror::Error, Debug, serde::Serialize)]
pub struct TimeOutOrRange(String);

impl fmt::Display for TimeOutOrRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// endregion: --- Error

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct TimeRfc3339(DateTime<Utc>);

impl TimeRfc3339 {
    pub const fn inner(&self) -> DateTime<Utc> {
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
        let new_time = Self::now_utc().0.checked_add_signed(time_delta).ok_or_else(|| {
            TimeOutOrRange(format!(
                "{} + {}msec",
                Self::now_utc().0,
                time_delta.num_milliseconds()
            ))
        })?;
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

impl<'de> serde::de::Deserialize<'de> for TimeRfc3339 {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let temp = String::deserialize(deserializer).map(|v| Self::parse_utc(&v));

        match temp {
            Ok(v) => v.map_err(|v| {
                serde::de::Error::custom(format!("Invalid Rfc3339 time format: {v}",))
            }),
            Err(e) => Err(e),
        }
    }
}

impl serde::Serialize for TimeRfc3339 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
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
    #![allow(clippy::unwrap_used)]

    use super::*;
    use chrono::{Duration, TimeZone, Utc};
    use std::str::FromStr;

    #[test]
    fn vaild_rfc3339_string() {
        const TIME: &str = "2020-09-08T13:10:08.511Z";

        assert!(TimeRfc3339::try_from(TIME).is_ok());
    }

    #[test]
    fn parse_valid_rfc3339() {
        let s = "2024-01-01T12:00:00Z";
        let t = TimeRfc3339::parse_utc(s).unwrap();
        assert_eq!(t.format_time(), "2024-01-01T12:00:00+00:00");
    }

    #[test]
    fn parse_invalid_rfc3339() {
        let s = "not-a-time";
        assert!(TimeRfc3339::parse_utc(s).is_err());
    }

    #[test]
    fn from_str_works() {
        let s = "2024-01-01T12:00:00Z";
        let t = TimeRfc3339::from_str(s).unwrap();
        assert_eq!(t.format_time(), "2024-01-01T12:00:00+00:00");
    }

    #[test]
    fn try_from_str() {
        let s = "2024-01-01T12:00:00Z";
        let t = TimeRfc3339::try_from(s).unwrap();
        assert_eq!(t.format_time(), "2024-01-01T12:00:00+00:00");
    }

    #[test]
    fn from_datetime() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
        let t: TimeRfc3339 = dt.into();
        assert_eq!(t.inner(), dt);
    }

    #[test]
    fn deref_works() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
        let t: TimeRfc3339 = dt.into();

        // Deref should give access to DateTime<Utc>
        assert_eq!(t.timestamp(), dt.timestamp());
    }

    #[test]
    fn format_time() {
        let dt = Utc.with_ymd_and_hms(2024, 5, 10, 8, 30, 0).unwrap();
        let t: TimeRfc3339 = dt.into();
        assert_eq!(t.format_time(), "2024-05-10T08:30:00+00:00");
    }

    #[test]
    fn now_utc_plus_sec_str_future() {
        let res = TimeRfc3339::now_utc_plus_sec_str(Duration::seconds(60));
        assert!(res.is_ok());

        let parsed = TimeRfc3339::parse_utc(&res.unwrap());
        assert!(parsed.is_ok());
    }

    #[test]
    fn serde_roundtrip() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
        let t: TimeRfc3339 = dt.into();

        let json = serde_json::to_string(&t).unwrap();
        let back: TimeRfc3339 = serde_json::from_str(&json).unwrap();

        assert_eq!(t, back);
    }

    #[test]
    fn serde_invalid_format() {
        let json = "\"invalid-time\"";
        let res: Result<TimeRfc3339, _> = serde_json::from_str(json);
        assert!(res.is_err());
    }
}
// endregion: --- Tests
