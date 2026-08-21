//! Wire constraint: uint32 port > 65535 must be rejected, not truncated.

use fleetos_control::policy::port_validation;

#[test]
fn port_above_65535_is_rejected() {
    let result = port_validation::validate_port(65536);
    assert!(result.is_err(), "port 65536 should be rejected");

    let result = port_validation::validate_port(u32::MAX);
    assert!(result.is_err(), "port u32::MAX should be rejected");
}

#[test]
fn valid_ports_are_accepted() {
    assert_eq!(port_validation::validate_port(0).unwrap(), 0);
    assert_eq!(port_validation::validate_port(80).unwrap(), 80);
    assert_eq!(port_validation::validate_port(65535).unwrap(), 65535);
}
