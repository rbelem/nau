use std::num::NonZeroU32;

use nau_core::resource_limit::{CpuMax, DegradeReason, MachinePercent, ResourceLimit};

fn percent(value: &str) -> MachinePercent {
    match ResourceLimit::resolve(Some(value), None).unwrap() {
        ResourceLimit::Percent(percent) => percent,
        ResourceLimit::Off => panic!("expected a percentage"),
    }
}

#[test]
fn resolution_uses_flag_then_env_then_default() {
    assert_eq!(
        ResourceLimit::resolve(None, None).unwrap(),
        ResourceLimit::DEFAULT
    );
    assert_eq!(
        ResourceLimit::resolve(Some("50"), Some("off")).unwrap(),
        ResourceLimit::Percent(percent("50"))
    );
    assert_eq!(
        ResourceLimit::resolve(Some("50"), Some("invalid")).unwrap(),
        ResourceLimit::Percent(percent("50"))
    );
    assert_eq!(
        ResourceLimit::resolve(None, Some("off")).unwrap(),
        ResourceLimit::Off
    );
    assert_eq!(
        ResourceLimit::resolve(None, Some("1")).unwrap(),
        ResourceLimit::Percent(percent("1"))
    );
    assert_eq!(
        ResourceLimit::resolve(None, Some("100")).unwrap(),
        ResourceLimit::Percent(percent("100"))
    );
}

#[test]
fn invalid_values_name_their_input_field() {
    for value in ["0", "101", "960", "80%", "2.5", "OFF", "", " ", "+1"] {
        let flag = ResourceLimit::resolve(Some(value), None)
            .unwrap_err()
            .to_string();
        assert!(flag.contains("--resource-limit"), "{value:?}: {flag}");

        let env = ResourceLimit::resolve(None, Some(value))
            .unwrap_err()
            .to_string();
        assert!(env.contains("NAU_RESOURCE_LIMIT"), "{value:?}: {env}");
    }
}

#[test]
fn cpu_max_uses_machine_cpu_count_and_fixed_period() {
    assert_eq!(
        CpuMax::from_machine(percent("80"), NonZeroU32::new(12).unwrap()).file_text(),
        "960000 100000"
    );
    assert_eq!(
        CpuMax::from_machine(percent("100"), NonZeroU32::new(12).unwrap()).file_text(),
        "1200000 100000"
    );
    assert_eq!(
        CpuMax::from_machine(percent("1"), NonZeroU32::new(1).unwrap()).file_text(),
        "1000 100000"
    );
}

#[test]
fn quota_core_floor_never_becomes_zero() {
    let one_cpu = CpuMax::from_machine(percent("80"), NonZeroU32::new(1).unwrap());
    let twelve_cpus = CpuMax::from_machine(percent("80"), NonZeroU32::new(12).unwrap());
    assert_eq!(one_cpu.whole_cores().get(), 1);
    assert_eq!(twelve_cpus.whole_cores().get(), 9);
}

#[test]
fn resource_limit_wire_values_are_validated() {
    assert_eq!(
        serde_json::to_string(&ResourceLimit::Percent(percent("80"))).unwrap(),
        "80"
    );
    assert_eq!(
        serde_json::to_string(&ResourceLimit::Off).unwrap(),
        "\"off\""
    );
    assert_eq!(
        serde_json::from_str::<ResourceLimit>("80").unwrap(),
        ResourceLimit::Percent(percent("80"))
    );
    assert_eq!(
        serde_json::from_str::<ResourceLimit>("\"off\"").unwrap(),
        ResourceLimit::Off
    );
    for value in ["0", "101", "80.0", "\"OFF\"", "\"80\"", "{}"] {
        let error = serde_json::from_str::<ResourceLimit>(value)
            .unwrap_err()
            .to_string();
        assert!(error.contains("resource_limit"), "{value}: {error}");
    }
}

#[test]
fn default_detection_and_degrade_names_are_stable() {
    assert!(ResourceLimit::DEFAULT.is_default());
    assert!(!ResourceLimit::Off.is_default());
    assert_eq!(
        serde_json::to_string(&DegradeReason::NoCpuController).unwrap(),
        "\"no_cpu_controller\""
    );
}
