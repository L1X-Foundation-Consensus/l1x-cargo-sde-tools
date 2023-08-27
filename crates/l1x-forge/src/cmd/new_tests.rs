use crate::cmd::new::*;

use std::path::PathBuf;

#[test]
fn test_new_contract_project_valid_name() {
    // Arrange
    let name = "my_contract";
    let template_name = None;
    let proj_base_path: Option<PathBuf> = None;

    // Act
    let result = new_contract_project(name, template_name, proj_base_path);

    // Assert
    assert!(result.is_ok());
}

#[test]
fn test_new_contract_project_invalid_name() {
    // Arrange
    let name = "my-contract-123"; // invalid because it does not begin with an alphabetic character
    let template_name = None;
    let proj_base_path: Option<PathBuf> = None;

    // Act
    let result = new_contract_project(name, template_name, proj_base_path);

    // Assert
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "Contract names must begin with an alphabetic character"
    );
}

#[test]
fn test_new_contract_project_existing_project_dir() {
    // Arrange
    let name = "my_contract";
    let template_name = None;
    let proj_base_path = Some(PathBuf::from(".")); // this directory already contains a Cargo.toml file

    // Act
    let result = new_contract_project(name, template_name, proj_base_path);

    // Assert
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "A Cargo package already exists in ."
    );
}
