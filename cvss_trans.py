none_low_high = {
    "N": "None", 
    "L": "Low",
    "H": "High"
}

cvss_titles = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope", 
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability"
}

cvss_score = {
    "AV": {
        "N": "Network",
        "L": "Local",
        "P": "Physical",
        "A": "Adjacent"
    },
    "AC": {
        "L": "Low",
        "H": "High"
    },
    "PR": none_low_high,
    "UI": {
        "N": "None",
        "R": "Required"
    },
    "S": {
        "U": "Unchanged",
        "C": "Changed"
    },
    "C": none_low_high,
    "I": none_low_high,
    "A": none_low_high
}