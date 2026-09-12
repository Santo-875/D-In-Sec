from __future__ import annotations
from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field
class Logtemplate(str,Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    SIGNUP_SUCCESS = "SIGNUP_SUCCESS"
    LOGOUT = "LOGOUT"
    DASHBOARD_ACCESS = "DASHBOARD_ACCESS"
    PROFILE_UPDATE = "PROFILE_UPDATE"
    DOCUMENT_UPLOAD = "DOCUMENT_UPLOAD"
    UPLOAD_REJECTED = "UPLOAD_REJECTED"
    VERIFY_UNAUTHORIZED = "VERIFY_UNAUTHORIZED"
    VERIFY_RESULT = "VERIFY_RESULT"
    VAULT_ACCESS = "VAULT_ACCESS"
    VAULT_STORE = "VAULT_STORE"
    UNKNOWN = "UNKNOWN"
class ParsedLogLine(BaseModel):
    timestamp:datetime
    level:str
    raw_message:str
    template: Logtemplate=Logtemplate.UNKNOWN
    source_file:str="system.log"
    actor_id: Optional[str] = None
class PIIEntityFound(BaseModel):
    pii_type:str
    count:int
class MaskedLogResult(BaseModel):
    original_template:Logtemplate
    masked_template:str
    pii_entities_found:List[PIIEntityFound]=Field(default_factory=list)
    masking_applied:bool
class IncidentType(str,Enum):
    SQL_INJECTION= "SQL_INJECTION"
    BRUTE_FORCE = "BRUTE_FORCE"
    MALICIOUS_UPLOAD = "MALICIOUS_UPLOAD"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    PII_LEAK = "PII_LEAK"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"
class Severity(str,Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
class ClassificationResult(BaseModel):
    incident_type:IncidentType
    severity:Severity
    confidence:float=Field(ge=0.0,le=1.0)
    cert_in_report_draft:Optional[str]=None
    source:str="llm"
class ProcessedLogEntry(BaseModel):
    parsed:ParsedLogLine
    masked:MaskedLogResult
    classification:Optional[ClassificationResult]=None