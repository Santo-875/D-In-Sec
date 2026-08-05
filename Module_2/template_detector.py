from schemas import ParsedLogLine, Logtemplate
import re
def detect_template(parsed: ParsedLogLine) -> ParsedLogLine:
    msg = parsed.raw_message
    if "logged in successfully" in msg:
        parsed.template = Logtemplate.LOGIN_SUCCESS
    elif "New user account created" in msg:
        parsed.template = Logtemplate.SIGNUP_SUCCESS
    elif "updated profile" in msg:
        parsed.template = Logtemplate.PROFILE_UPDATE
    elif "uploaded document" in msg:
        parsed.template = Logtemplate.DOCUMENT_UPLOAD
    elif "Failed login attempt" in msg:
        parsed.template = Logtemplate.LOGIN_FAILED
    elif "logged out" in msg:
        parsed.template = Logtemplate.LOGOUT
    elif "File upload rejected" in msg:
        parsed.template = Logtemplate.UPLOAD_REJECTED
    elif "accessed dashboard" in msg:
        parsed.template = Logtemplate.DASHBOARD_ACCESS
    elif "Unauthorized verify attempt" in msg:
        parsed.template = Logtemplate.VERIFY_UNAUTHORIZED
    elif "verification PENDING" in msg or "marked as Verified" in msg:
        parsed.template = Logtemplate.VERIFY_RESULT
    else:
        parsed.template = Logtemplate.UNKNOWN
    return parsed
