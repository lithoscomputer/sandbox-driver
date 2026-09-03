#[test]
fn cli_contract() {
    trycmd::TestCases::new().case("tests/cmd/*.toml");
}
