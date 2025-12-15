import torch
from transformers import AutoTokenizer
from peft import AutoPeftModelForCausalLM

LORA_PATH = "./lora"

# Tokenizer: load from adapter (it already copied tokenizer files)
tokenizer = AutoTokenizer.from_pretrained(
    LORA_PATH,
    trust_remote_code=True
)

# AutoPeft loader (reads base model from adapter_config.json)
model = AutoPeftModelForCausalLM.from_pretrained(
    LORA_PATH,
    torch_dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True,
    local_files_only=False
)

model.eval()

print("✅ LoRA + base model loaded successfully")
prompt = """<|system|>
You are a defensive web security analysis model.

Rules:
- Only classify vulnerabilities
- Do NOT generate exploits or payloads
- Output strictly valid JSON
<|user|>
Analyze the following website structure and recommend relevant security scans.

HTML_SNIPPET:
<form method="POST" action="/login">
  <input type="text" name="username">
  <input type="password" name="password">
</form>

FORMS_SUMMARY:
- POST /login
- Inputs: username, password
- CSRF token: not detected

HEADERS_SUMMARY:
- Content-Security-Policy: missing

TECH_STACK:
PHP, Apache, MySQL
<|assistant|>
"""

inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

with torch.no_grad():
    out = model.generate(
        **inputs,
        max_new_tokens=300,
        temperature=0.1,
        do_sample=False
    )

print(tokenizer.decode(out[0], skip_special_tokens=True))

