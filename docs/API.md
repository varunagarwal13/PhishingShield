# PhishingShield REST API Documentation

## Endpoints

### 1. GET `/live`
Returns the operational liveliness check.

### 2. POST `/analyse`
Analyzes a URL input string.

**Request Schema**:
```json
{
  "url": "https://paypal-security-update.com/login"
}
```

**Response Schema**:
```json
{
  "verdict": "BLOCK",
  "risk_score": 85.0,
  "reasons": [
    "Lexical brand impersonation anomaly detected"
  ],
  "mitre_mappings": [
    "T1566"
  ]
}
```
