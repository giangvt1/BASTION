import os
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from modules.log_parser import parse_cloudtrail_logs
import json

def run_soc_agent():
    # Load environment variables
    load_dotenv()
    
    # Ensure API Key is available
    if not os.getenv("GEMINI_API_KEY"):
        print("Error: GEMINI_API_KEY not found in environment variables.")
        return

    # 1. Load Logs
    log_file_path = "CloudTRail.json"
    print(f"Reading logs from {log_file_path}...")
    
    logs = parse_cloudtrail_logs(log_file_path, "AccessDenied")
    if not logs:
        print("No 'AccessDenied' logs found to analyze.")
        return
        
    logs_str = json.dumps(logs, indent=2)

    # 2. Define the LangChain Prompt Template
    # This specifies the exact persona and Chain-of-Thought required by the user
    system_prompt = """Bạn là một chuyên gia an ninh mạng SOC. Hãy phân tích file log AWS CloudTrail này theo phương pháp Chain-of-Thought (suy luận từng bước).

Sau quá trình phân tích (Chain-of-Thought), BẮT BUỘC bạn phải tóm tắt lại kết quả cuối cùng theo ĐÚNG cấu trúc 4 phần sau (không được thiếu):
1. **IP Nguồn**: (Xác định IP gốc truy cập)
2. **User**: (Xác định User/Role nào đang thực hiện)
3. **Chiến thuật tấn công (MITRE ATT&CK)**: (Ánh xạ các hành động sang chiến thuật của MITRE)
4. **Đề xuất cách xử lý (Remediation steps)**: (Đưa ra các bước cụ thể để ngăn chặn/khắc phục, ví dụ như block IP, đổi credential, v.v...)"""

    human_message = """Dưới đây là các log AWS CloudTrail đã được lọc lỗi AccessDenied:
<logs>
{cloudtrail_logs}
</logs>

Vui lòng phân tích."""

    prompt_template = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", human_message)
    ])

    # 3. Initialize the Gemini LLM
    print("Khởi tạo LangChain SOC Agent với mô hình Gemini 2.5 Flash...")
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0.2, # Low temperature for analytical consistency
        max_tokens=2048
    )

    # 4. Create the Chain
    chain = prompt_template | llm

    # 5. Execute Chain and Print
    print("\nĐang phân tích logs...")
    print("="*60)
    print("Kết quả phân tích từ SOC Agent (Chain-of-Thought):")
    print("="*60)
    
    try:
        response = chain.invoke({"cloudtrail_logs": logs_str})
        print(response.content)
    except Exception as e:
        print(f"Lỗi khi chạy Agent: {e}")
        
    print("="*60)

if __name__ == "__main__":
    run_soc_agent()
