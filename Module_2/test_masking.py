from masking.regex import mask_structured_pii

test_line = 'User newuser (newuser@example.com) updated profile: full_name=John Doe, dob=1990-05-15, aadhaar=123456789012, pan=ABCDE1234F, phone=9876543210, address=123 Main St, Tech City from IP 127.0.0.1'

masked, found = mask_structured_pii(test_line)
print('MASKED:', masked)
print('FOUND:', found)
