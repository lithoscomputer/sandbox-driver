use std::env;

#[test]
fn cli_contract() {
    let cases = trycmd::TestCases::new();
    if let Some(profile_file) = env::var_os("LLVM_PROFILE_FILE") {
        cases.env(
            "LLVM_PROFILE_FILE",
            profile_file.to_string_lossy().into_owned(),
        );
    }
    cases.case("tests/cmd/*.toml");
}
