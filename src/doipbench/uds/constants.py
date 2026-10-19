"""UDS constants (ISO 14229-1)."""

from __future__ import annotations

from enum import IntEnum


class ServiceId(IntEnum):
    """Service identifiers implemented or referenced by the test bench."""

    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    SECURITY_ACCESS = 0x27
    READ_DATA_BY_IDENTIFIER = 0x22
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    TESTER_PRESENT = 0x3E
    READ_DTC_INFORMATION = 0x19


class NegativeResponseCode(IntEnum):
    """Negative response codes used by the virtual ECU."""

    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_MESSAGE_LENGTH = 0x13
    RESPONSE_TOO_LONG = 0x14
    BUSY_REPEAT_REQUEST = 0x21
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    INVALID_KEY = 0x35
    EXCEED_NUMBER_OF_ATTEMPTS = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
    GENERAL_PROGRAMMING_FAILURE = 0x72
    SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E
    SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7F


class Session(IntEnum):
    """Diagnostic session types."""

    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED = 0x03
    SAFETY_SYSTEM = 0x04


class DtcReportType(IntEnum):
    """Sub-functions of service 0x19 used in this project."""

    REPORT_NUMBER_OF_DTC_BY_STATUS_MASK = 0x01
    REPORT_DTC_BY_STATUS_MASK = 0x02
    REPORT_DTC_SNAPSHOT_RECORD_BY_DTC_NUMBER = 0x04
    REPORT_DTC_EXT_DATA_RECORD_BY_DTC_NUMBER = 0x06
    REPORT_SUPPORTED_DTC = 0x0A


class DtcStatus(IntEnum):
    """Bit masks of the DTC status byte."""

    TEST_FAILED = 0x01
    TEST_FAILED_THIS_OPERATION_CYCLE = 0x02
    PENDING_DTC = 0x04
    CONFIRMED_DTC = 0x08
    TEST_NOT_COMPLETED_SINCE_LAST_CLEAR = 0x10
    TEST_FAILED_SINCE_LAST_CLEAR = 0x20
    TEST_NOT_COMPLETED_THIS_OPERATION_CYCLE = 0x40
    WARNING_INDICATOR_REQUESTED = 0x80


#: Positive response SID is always ``request SID + 0x40``.
POSITIVE_RESPONSE_OFFSET = 0x40

#: Bit 7 of a sub-function disables the positive response.
SUPPRESS_POSITIVE_RESPONSE = 0x80

#: Mask used to strip the suppress bit.
SUB_FUNCTION_MASK = 0x7F
