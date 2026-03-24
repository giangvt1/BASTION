# BASTION: Báo Cáo Chi Tiết Thiết Kế Giải Pháp (Solution Design)

## 📌 Tóm Tắt Khái Quát (Executive Summary)
**BASTION** không phải là một "Chatbot AI" đơn thuần. Đây là một **Hệ sinh thái Đa đặc vụ Tự trị (Autonomous Multi-Agent System)** được thiết kế đặc biệt để giải quyết căn bệnh "Tràn ngập cảnh báo giả" (Alert Fatigue) trong các Trung tâm Điều hành An ninh mạng (SOC). 

Thiết kế của BASTION chia làm **5 tầng (Layers)** tách biệt hoàn toàn, đảm bảo khả năng mở rộng (Scalability), năng lực suy luận tự trị (Agentic Reasoning), tính riêng tư dữ liệu (Privacy-by-Design) và tối ưu hóa chi phí (Cost-optimized Data Strategy).

---

## ⚙️ Chi Thiết Kế Từng Tầng (Layer-by-Layer Architecture)

### Layer 1: Ingestion & Privacy (Tầng Tiếp nhận & Lọc dữ liệu cá nhân)
- **Vấn đề (Problem):** Dữ liệu khổng lồ từ Firewall, Email, hệ thống Cloud bắn về SIEM liên tục. Trong đó chứa vô số thông tin nhạy cảm của khách hàng (PII, số thẻ tín dụng, email cá nhân) gây vi phạm luật bảo vệ dữ liệu (GDPR, PDPA).
- **Giải quyết (Solution):** 
  - Các Artifacts (File Log, Email) được tiếp nhận qua FastAPI (mô phỏng AWS EventBridge). 
  - Ngay lập tức, luồng dữ liệu phải đi qua module **Tier 1 PII Scrubber**. Module này sử dụng các kỹ thuật RegEx học máy để băm nát và mã hóa (Masking) toàn bộ dữ liệu nhạy cảm trước khi cho phép dữ liệu này chạm tới bất kỳ con AI nào.
  - **Giá trị cốt lõi:** Đáp ứng tuyệt đối tính tuân thủ pháp lý (Compliance ready).

### Layer 2: Event Buffering & Pre-filtering (Tầng Đệm & Sàng Lọc Thô)
- **Vấn đề (Problem):** Gửi mọi cảnh báo lên mô hình Ngôn ngữ lớn (LLM) là một sự lãng phí tiền bạc khủng khiếp (Chi phí Token) và gây thắt cổ chai về hiệu năng (Rate Limits).
- **Giải quyết (Solution):**
  - **AWS SQS (Simple Queue Service):** Gom nhóm sự cố vào hàng chờ để dập tắt các đợt bùng nổ traffic (Spike traffic).
  - **Rule-based/ML Classifier:** Sàng lọc qua các luật tĩnh trước. Chỉ những cảnh báo có rủi ro đáng kể (High Entropy) mới được kích hoạt trích xuất IOC và đẩy qua cho AI xử lý. Phế phẩm (False Positive) bị huỷ ngay từ vòng gửi xe.
  - **Giá trị cốt lõi:** Tiết kiệm hàng chục ngàn đô la chi phí vận hành AI (Cost-efficiency).

### Layer 3: Multi-Agent Orchestration (Lõi LangGraph Tự Trị)
- **Vấn đề (Problem):** Chatbot AI (như ChatGPT/Claude) thường bị **ảo giác (Hallucination)**. Chúng hay bịa ra kết quả, thiếu khả năng thực thi luồng công việc nhiều bước (Multi-step workflow) đòi hỏi việc tra cứu tool và phân loại độc lập.
- **Giải quyết (Solution):** Áp dụng kiến trúc **Máy Trạng Thái Đa Đặc Vụ (Autonomous LangGraph)**, trong đó AI được chia nhỏ thành 5 vai trò độc lập:
  1. **Supervisor (Trưởng Nhóm):** Không phân tích dữ liệu, chỉ làm nhiệm vụ Cầm trịch định tuyến (Routing). Chống việc các Agent chạy lòng vòng vô hạn.
  2. **Email Analyst:** Mổ xẻ header, check SPF/DKIM, bóc tách chuỗi URL và IP ẩn giấu.
  3. **Threat Intel:** Kiểm tra độ uy tín của IP/Domain (OSINT) thông qua công cụ API (VirusTotal/Pinecone DB).
  4. **Forensic Analyst (Siêu quan trọng):** Đội ngũ chống ảo giác. Con AI này BẮT BUỘC phải dùng công cụ dịch SQL để truy vấn vào kho Log (AWS Athena). Nếu nó không tìm thấy Email/IP đó gây hại trong cấu trúc Log thật sự, nó không được quyền kết luận án phạt. Mọi bằng chứng phải là "Hard Evidence".
  5. **Synthesis:** Tập hợp bằng chứng từ 3 con AI trên để sinh ra mã nguồn ứng phó (Sigma Rule) và tóm tắt theo cấu trúc Markdown chuẩn Enterprise.

### Layer 4: Data Lakehouse Strategy (Chiến lược Lưu trữ Thông minh)
- **Vấn đề (Problem):** Việc nhồi nhét hàng Terabytes dữ liệu CloudTrail/Network Log vào các Cơ sở dữ liệu nóng (Elasticsearch, SQL) tốn chi phí cơ sở hạ tầng cực kỳ đắt đỏ.
- **Giải quyết (Solution):** 
  - **Cold Storage:** Toàn bộ Logs rác được đổ xuống thùng chứa AWS S3 (giá cực rẻ).
  - **Serverless Query:** Áp dụng AWS Athena. Chỉ khi con Agent Forensic nghi ngờ có biến, nó mới gõ lệnh SQL lên Athena để lục lại cái đống S3 trên. Không quét thì không tốn tiền.
  - **Hot Store:** AWS DynamoDB CHỈ dùng để lưu lại file báo cáo (Report JSON) dung lượng siêu siêu nhỏ cuối cùng của sự cố.
  - **Giá trị cốt lõi:** Thiết kế hạ tầng siêu tiết kiệm điện toán, cho khả năng Scalability vô hạn mà không sợ bị phồng chi phí (Cost Bloat).

### Layer 5: Real-time Observability & HiTL (Giao diện Giám sát & Con người Can thiệp)
- **Vấn đề (Problem):** AI Blackbox (Hộp đen) khiến kỹ sư SOC không dám tin tưởng giao quyền tự động khoá tài khoản thao tác xoá.
- **Giải quyết (Solution):**
  - **Live Console (Agent Inspector):** Frontend (React) móc nối trực tiếp liên tục vào `pipeline_logs` của từng Agent. Khi bấm vào Forensic, màn hình sẽ hiển thị theo thời gian thực (Real-time) từng suy nghĩ và hành động dò tìm SQL log của con Agent. Minhh bạch tuyệt đối mọi hành vi của AI (Explainable AI).
  - **Human-in-The-Loop (HiTL):** AI chỉ đưa ra các phương án ứng phó đính kèm chứng cứ và Sigma Rule. Người quản trị (Kỹ sư thật) đóng vai trò thẩm định viên cuối cùng để bấm nút DUNG THỨ (False Positive) hoặc ỨNG PHÓ (Escalate/Approve), sau đó nút này mới đẩy mã lệnh lên tường lửa. Đảm bảo an toàn 100%.

---

## 🎯 Tổng Kết Giá Trị Kinh Doanh (Business Impact Summary)
Mô hình **Decoupled Architecture** (Kiến trúc phi tập trung) này cho phép BASTION hoạt động xuất sắc mà không bắt Doanh nghiệp phải đập bỏ Firewall hay hệ thống mạng cũ. Sự phối hợp của Đội Đặc vụ Tự trị giúp rút ngắn Chu kỳ Phản ứng Sự cố (MTTR - Mean Time To Respond) **từ 30-45 phút do dọn rác thủ công xuống chỉ còn 30 giây rà soát chéo tự động**. Thép đã tôi thế đấy!
