PII_ENTITY_LABELS = {"PERSON", "GPE", "LOC", "ORG"}

nlp = None

def mask_named_entities(text: str) -> tuple[str, list[dict]]:
    global nlp
    if nlp is None:
        import spacy
        nlp = spacy.load("en_core_web_md")
    
    doc = nlp(text)
    entities_to_mask = []
    for ent in doc.ents:
        if ent.label_ not in PII_ENTITY_LABELS:
            continue
            
        # Ignore our own placeholders
        if "REDACTED" in ent.text or "HASHED" in ent.text:
            continue
            
        # Ignore structural logging keys/values (e.g., event=VAULT_ACCESS)
        if "=" in ent.text:
            continue
        
        # Check surrounding characters
        prev_char = text[ent.start_char - 1] if ent.start_char > 0 else ""
        next_char = text[ent.end_char] if ent.end_char < len(text) else ""
        
        if prev_char in ('=', '[', '_') or next_char in ('=', ']', '_'):
            continue
            
        entities_to_mask.append(ent)

    entity_counts = {}
    for ent in entities_to_mask:
        entity_counts[ent.label_] = entity_counts.get(ent.label_, 0) + 1

    for ent in reversed(entities_to_mask):
        text = text[:ent.start_char] + f"[REDACTED_{ent.label_}]" + text[ent.end_char:]

    entities_found = [
        {"pii_type": label, "count": count} for label, count in entity_counts.items()
    ]

    return text, entities_found