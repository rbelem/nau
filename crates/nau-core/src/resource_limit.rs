use std::fmt;
use std::num::{NonZeroU32, NonZeroUsize};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MachinePercent(u8);

impl MachinePercent {
    pub const DEFAULT: Self = Self(50);

    pub const fn get(self) -> u8 {
        self.0
    }

    fn new(value: u8) -> Result<Self, &'static str> {
        if (1..=100).contains(&value) {
            Ok(Self(value))
        } else {
            Err("resource_limit must be an integer from 1 to 100")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceLimit {
    Percent(MachinePercent),
    Off,
}

impl ResourceLimit {
    pub const DEFAULT: Self = Self::Percent(MachinePercent::DEFAULT);

    pub fn resolve(flag: Option<&str>, env: Option<&str>) -> miette::Result<Self> {
        match (flag, env) {
            (Some(value), _) => Self::parse(value, "--resource-limit"),
            (None, Some(value)) => Self::parse(value, "NAU_RESOURCE_LIMIT"),
            (None, None) => Ok(Self::DEFAULT),
        }
    }

    pub fn is_default(self) -> bool {
        self == Self::DEFAULT
    }

    pub const fn percent(self) -> Option<MachinePercent> {
        match self {
            Self::Percent(percent) => Some(percent),
            Self::Off => None,
        }
    }

    fn parse(value: &str, field: &str) -> miette::Result<Self> {
        let invalid = || miette::miette!("{field} must be 'off' or an integer from 1 to 100");
        if value == "off" {
            return Ok(Self::Off);
        }
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let value = value.parse::<u8>().map_err(|_| invalid())?;
        MachinePercent::new(value)
            .map(Self::Percent)
            .map_err(|_| invalid())
    }
}

impl Default for ResourceLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Serialize for ResourceLimit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Percent(percent) => serializer.serialize_u8(percent.get()),
            Self::Off => serializer.serialize_str("off"),
        }
    }
}

impl<'de> Deserialize<'de> for ResourceLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResourceLimitVisitor;

        impl Visitor<'_> for ResourceLimitVisitor {
            type Value = ResourceLimit;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("resource_limit as an integer from 1 to 100 or 'off'")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = u8::try_from(value)
                    .map_err(|_| E::custom("resource_limit must be from 1 to 100"))?;
                MachinePercent::new(value)
                    .map(ResourceLimit::Percent)
                    .map_err(E::custom)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = u64::try_from(value)
                    .map_err(|_| E::custom("resource_limit must be from 1 to 100"))?;
                self.visit_u64(value)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "off" {
                    Ok(ResourceLimit::Off)
                } else {
                    Err(E::custom("resource_limit string must be 'off'"))
                }
            }
        }

        deserializer.deserialize_any(ResourceLimitVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    quota_us: u64,
    period_us: u64,
}

impl CpuMax {
    pub const PERIOD_US: u64 = 100_000;

    pub fn from_machine(percent: MachinePercent, online_cpus: NonZeroU32) -> Self {
        Self {
            quota_us: u64::from(percent.get()) * u64::from(online_cpus.get()) * Self::PERIOD_US
                / 100,
            period_us: Self::PERIOD_US,
        }
    }

    pub fn file_text(self) -> String {
        format!("{} {}", self.quota_us, self.period_us)
    }

    pub fn whole_cores(self) -> NonZeroUsize {
        let cores = (self.quota_us / self.period_us).max(1) as usize;
        NonZeroUsize::new(cores).expect("the quota floor is at least one core")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradeReason {
    NoCgroupV2,
    NoCpuController,
    NoWritableParent,
    CpuCountUnknown,
}
