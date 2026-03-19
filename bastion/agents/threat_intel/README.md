# Threat Intelligence Agent

> **Banking Agentic Security Threat Intelligence & Orchestration Network**
>
> Sub-agent chuyên enrichment IOCs và đánh giá mức độ đe dọa

---

## Mục tiêu

Nhận IOCs (IP, domain, hash, URL, email) từ các agent khác qua `BastionState`, sau đó:
- Scan reputation qua VirusTotal, AbuseIPDB (planned)
- Check domain age + WHOIS (planned)
- IP geolocation & ASN analysis (planned)
- Correlate IOCs với known campaigns
- Map findings vào MITRE ATT&CK

---

## Trạng thái hiện tại

> **⚠️ Skeleton Implementation** -- Hiện tại agent đang ở trạng thái cơ bản:
> - Gọi Gemini LLM với list IOCs để đánh giá
> - Chưa có tool-calling / ReAct loop
> - Chưa có external API integration (VirusTotal, AbuseIPDB)
> - LLM response chưa được parse thành structured findings

### Planned Enhancements

1. **ReAct workflow** với các tools:
   - `virustotal_lookup` (IP/Domain/Hash reputation)
   - `abuseipdb_check` (IP abuse report)
   - `whois_lookup` (Domain registration, age)
   - `ip_geolocation` (GeoIP + ASN)
2. **Pydantic structured output** (ThreatIntelOutput model)
3. **Confidence scoring** cho mỗi IOC
4. **Campaign correlation** với threat actor databases

---

## Luồng hiện tại

```
          IOCs from BastionState
                   │
                   ▼
          Build prompt with IOC list
                   │
                   ▼
          Call Gemini LLM (raw text)
                   │
                   ▼
          Log response (TODO: parse)
                   │
                   ▼
          Return findings: [] (skeleton)
```

---

## File

```
bastion/agents/threat_intel.py
```

---

## Input

```python
state["iocs"] = [
    {"ioc_type": "ip", "value": "185.220.101.45", "source_agent": "forensic_analyst", "context": "Foreign IP used for login"},
    {"ioc_type": "domain", "value": "secure-login.com", "source_agent": "email_analyst", "context": "Typo-squatting domain"},
]
```

---

## Dependencies

- `bastion.services.gemini` (call_gemini)
- `bastion.models.state` (BastionState)
- `langchain_core.messages` (AIMessage)


---

## ML Integration Context

Threat Intel Agent hiện tại chưa có ML integration, nhưng có thể được enhance với:

### Future Enhancement: P3 - XGBoost IOC Risk Scorer

**Concept**: Train XGBoost model để score IOCs dựa trên:
- VirusTotal detection ratio
- AbuseIPDB confidence score
- Domain age (WHOIS)
- IP geolocation (country risk score)
- Historical appearance in incidents
- Correlation with known campaigns

**Benefits**:
- Structured risk scoring (0.0-1.0)
- Faster than LLM reasoning
- Consistent scoring across IOCs
- Can prioritize high-risk IOCs for manual review

**Training Data**: Requires labeled IOC dataset with reputation scores

**Status**: Planned (P3 priority)

See `ML_ENHANCEMENTS_SUMMARY.md` for details.

---

## Related Documentation

- **ML Integration**: `ML_INTEGRATION.md`
- **System Design**: `Design.md`
- **Testing**: `TESTING.md`
