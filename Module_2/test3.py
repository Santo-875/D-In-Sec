from masking.regex import mask_structured_pii
from masking.ner_masking import mask_named_entities

test_line = "User habibi (myself@gmail.com) updated profile: full_name=Habibi kumar S, dob=2014-04-19, aadhaar=7171-7247-1875, pan=acda123adc, phone=88888777321, address=123 , tech park city , florida , united states from IP 127.0.0.1"
test_line_2 = "[2026-07-25 10:25:55] [WARNING] Failed login attempt for username 'wronguser' from IP 127.0.0.1"

for line in [test_line, test_line_2]:
    masked_text, regex_found = mask_structured_pii(line)
    masked_ner, ner_found = mask_named_entities(masked_text)

    print("RAW:   ", line)
    print("MASKED:", masked_ner)
    print()
