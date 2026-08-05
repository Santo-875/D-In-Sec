import spacy
nlp = spacy.load("en_core_web_md")
PII_ENTITY_LABELS = {"PERSON", "GPE", "LOC", "ORG"}

def mask_named_entities(text: str) -> tuple[str, list[dict]]:
    doc = nlp(text)
    entities_to_mask = [
        ent for ent in doc.ents 
        if ent.label_ in PII_ENTITY_LABELS 
        and not ent.text.startswith("HASHED_IP")
        and not ent.text.startswith("REDACTED")
    ]

    entity_counts = {}
    for ent in entities_to_mask:
        entity_counts[ent.label_] = entity_counts.get(ent.label_, 0) + 1

    for ent in reversed(entities_to_mask):
        text = text[:ent.start_char] + f"[REDACTED_{ent.label_}]" + text[ent.end_char:]

    entities_found = [
        {"pii_type": label, "count": count} for label, count in entity_counts.items()
    ]

    return text, entities_found