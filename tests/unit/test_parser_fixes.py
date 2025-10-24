"""Regression tests for the C type parser."""

from reveng.tools.quality.c_type_parser import CTypeParser


def test_pointer_parsing_extracts_parameter_details():
    parser = CTypeParser()
    signature = parser.parse_function_signature("int foo(const char *str)")

    assert signature is not None
    assert signature.parameters[0].name == "str"
    assert "const char" in str(signature.parameters[0].type)
    assert "*" in str(signature.parameters[0].type)


def test_array_parameter_preserves_name():
    parser = CTypeParser()
    signature = parser.parse_function_signature("int process(char buffer[256])")

    assert signature.parameters[0].name.startswith("buffer")
    assert "buffer" in signature.parameters[0].name
    assert "256" in signature.parameters[0].name


def test_address_field_parses_hex_and_decimal():
    parser = CTypeParser()
    sig_hex = parser.parse_function_signature("int foo(void)", "0x401000")
    sig_dec = parser.parse_function_signature("int bar(void)", "12345")
    sig_none = parser.parse_function_signature("int baz(void)", "")

    assert sig_hex.address == 0x401000
    assert sig_dec.address == 12345
    assert sig_none.address is None
