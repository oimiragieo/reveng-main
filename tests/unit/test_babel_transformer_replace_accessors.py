"""Regression tests for BabelTransformer._replace_accessors re.sub injection.

The decoded JS string-array elements were spliced directly into the re.sub
REPLACEMENT string as f"'{string}'". Backslash escapes (\\x41) and group
references (\\1) in obfuscated strings are then interpreted by re.sub, which
either raises re.error (invalid group reference) or mangles the output.
"""

import pytest

from reveng.javascript.babel_transformer import StringArrayDeobfuscator


def test_replace_accessors_group_ref_does_not_raise():
    """A string containing a backreference like \\1 must not raise re.error."""
    transformer = StringArrayDeobfuscator()
    string_array = ["before\\1after"]
    code = "var x = _0xabc(0);"

    # Must not raise (previously raised re.error: invalid group reference)
    result = transformer._replace_accessors(code, string_array)

    # The literal backslash-1 must survive verbatim, not be mangled.
    assert "'before\\1after'" in result


def test_replace_accessors_hex_escape_not_mangled():
    """A string containing \\x41 must be inserted literally, not mangled."""
    transformer = StringArrayDeobfuscator()
    string_array = ["\\x41BC"]
    code = "var x = _0xdef(0);"

    result = transformer._replace_accessors(code, string_array)

    # The literal \x41 must survive verbatim.
    assert "'\\x41BC'" in result


def test_replace_accessors_combined_escapes():
    """Combined \\x41 and \\1 in one element must not raise and not mangle."""
    transformer = StringArrayDeobfuscator()
    string_array = ["\\x41\\1"]
    code = "y = _0x1234(0);"

    result = transformer._replace_accessors(code, string_array)

    assert "'\\x41\\1'" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
