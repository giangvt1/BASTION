# Supervisor Agent (SOC Lead)

> **Banking Agentic Security Threat Intelligence & Orchestration Network**
>
> Agent điều phối trung tâm -- đóng vai SOC Team Lead

---

## Mục tiêu

Đọc event đầu vào + toàn bộ findings/IOCs hiện có, sau đó ra quyết định routing:
- Delegate cho sub-agent phù hợp (Email / Forensic / Threat Intel)
- Hoặc tổng hợp báo cáo cuối cùng (SYNTHESIZE)

**Không trực tiếp dùng tool phân tích** -- chỉ đọc state và lý luận.

---

## Luồng hoạt động

```
    START
      │
      ▼
  ┌──────────────┐     Iteration < MAX?
  │  Supervisor   │────── Yes ──▶ Call Gemini LLM
  │  (SOC Lead)   │                  │
  └──────┬───────┘            Parse Decision
         │                         │
   No (MAX reached)     ┌──────────┴──────────┐
         │              │          │           │
         ▼          DELEGATE   DELEGATE    DELEGATE
     SYNTHESIZE     _EMAIL     _FORENSIC   _THREAT
         │              │          │           │
         ▼              ▼          ▼           ▼
        END        email_analyst  forensic   threat_intel
                       │          analyst       │
                       │            │           │
                       └────────────┴───────────┘
                                    │
                              loop back to
                               Supervisor
```

---

## Anti-Infinite-Loop

Sử dụng `iteration_count` trong `BastionState` + `MAX_ITERATIONS = 10`:

```python
if iteration >= MAX_ITERATIONS:
    return {"next_agent": "SYNTHESIZE"}
```

Khi vượt quá giới hạn, Supervisor bắt buộc kết thúc bằng SYNTHESIZE.

---

## Routing Logic

1. **Build context**: Tổng hợp event_type, iteration count, tất cả findings + IOCs thành text
2. **Call Gemini**: Gửi context + system prompt, yêu cầu trả về 1 trong 4 lệnh
3. **Parse**: Regex match trên response để extract decision
4. **Fallback**: Nếu LLM lỗi hoặc response không parse được → mặc định SYNTHESIZE

### Routing Decisions

| Decision | Target Node | Mô tả |
|----------|-------------|-------|
| `DELEGATE_EMAIL` | `email_analyst` | Phân tích email .eml |
| `DELEGATE_FORENSIC` | `forensic_analyst` | Điều tra CloudTrail logs |
| `DELEGATE_THREAT` | `threat_intel` | IOC reputation scanning |
| `SYNTHESIZE` | `END` | Tổng hợp report, kết thúc graph |

---

## File

```
bastion/agents/supervisor.py
```

Không có thư mục riêng vì Supervisor đơn giản (không có tools/tier1 filter).

---

## Error-Aware Routing

Supervisor doc `error_logs` tu `BastionState` de tranh re-delegate toi agent da fail:

```python
error_logs = state.get("error_logs", [])
if error_logs:
    context += f"\nAgent Errors: {error_logs[-5:]}"
    context += "\nDo NOT re-delegate to failed agents."
```

Khi tat ca agent da loi hoac `MAX_ITERATIONS` vuot gioi han -> force `SYNTHESIZE`.

---

## Dependencies

- `bastion.services.gemini` (call_gemini)
- `bastion.models.state` (BastionState -- including error_logs)
- `langchain_core.messages` (AIMessage)
