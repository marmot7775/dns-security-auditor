def normalize_domain(value: str) -> str:
    if not value:
        return ""
    domain = str(value).strip().lower()
    
    # Handle email addresses (take everything after @)
    if "@" in domain:
        domain = domain.split("@")[-1]
        
    # Standard cleaning
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    
    # Handle port numbers
    if ":" in domain:
        domain = domain.partition(":")[0]
        
    return domain.rstrip(".")