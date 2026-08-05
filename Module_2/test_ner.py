from masking.regex import mask_structured_pii
from masking.ner_masking import mask_named_entities

test_line = 'User newuser (newuser@example.com) updated profile: full_name=John Doe, dob=1990-05-15, aadhaar=123456789012, pan=ABCDE1234F, phone=9876543210, address=123 Main St, Tech City from IP 127.0.0.1'

# Step 1: regex masking first
masked_regex, found_regex = mask_structured_pii(test_line)

# Step 2: NER masking on top
masked_final, found_ner = mask_named_entities(masked_regex)

print('AFTER REGEX:', masked_regex)
print()
print('AFTER NER:', masked_final)
print()
print('REGEX FOUND:', found_regex)
print('NER FOUND:', found_ner)
