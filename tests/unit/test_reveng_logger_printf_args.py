"""REVENGLogger accepts stdlib-style %-formatting args."""

from reveng.core.logger import REVENGLogger


def test_reveng_logger_warning_accepts_percent_args(caplog):
    logger = REVENGLogger("reveng.test.logger_arity")
    with caplog.at_level("WARNING", logger="reveng.test.logger_arity"):
        logger.warning("Behavioral monitoring failed: %s (%s)", "boom", 42)
    assert any("Behavioral monitoring failed: boom (42)" in r.message for r in caplog.records)


def test_reveng_logger_info_without_args_still_works(caplog):
    logger = REVENGLogger("reveng.test.logger_plain")
    with caplog.at_level("INFO", logger="reveng.test.logger_plain"):
        logger.info("plain message")
    assert any(r.message == "plain message" for r in caplog.records)
