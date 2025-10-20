#!/usr/bin/env python3
"""
qwen_vuln_detector.py

REAL INFERENCE: This script loads the fine-tuned Qwen model
from ./qwen-vuln-detector and performs local inference on
runtime vulnerability samples.
"""

import os, sys, json, time, random, argparse, torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

BANNER = """
==============================================================
 QWEN-VULN-DETECTOR (LOCAL INFERENCE)
==============================================================
 Using fine-tuned Qwen model from ./qwen-vuln-detector
 to classify and describe security vulnerabilities.
==============================================================
"""

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MODEL_PATH = "./qwen-vuln-detector"

class QwenVulnDetector:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        self.model = AutoModelForCausalLM.from_pretrained(MODEL_PATH).to(DEVICE)
        self.pipeline = pipeline("text-generation", model=self.model, tokenizer=self.tokenizer, device=0 if DEVICE=="cuda" else -1)

    def infer(self, payload):
        prompt = (
            f"Identify the vulnerability type from this input:\n"
            f"{json.dumps(payload, indent=2)}\n"
            f"Answer:"
        )
        outputs = self.pipeline(prompt, max_length=256, num_return_sequences=1, temperature=0.1, top_p=0.9, do_sample=False)
        return outputs[0]["generated_text"].replace(prompt, "").strip()

def spinner(label="QWEN"):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    for i in range(20):
        sys.stdout.write(f"\r[{label}] {frames[i % len(frames)]} running inference...")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 60 + "\r")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", default="cookie-security")
    parser.add_argument("--subtype", default="js-cookie-set")
    parser.add_argument("--url", default="http://127.0.0.1:5000/comments")
    parser.add_argument("--match", default="+document.cookie")
    args = parser.parse_args()

    payload = {
        "type": args.type,
        "subtype": args.subtype,
        "url": args.url,
        "match": args.match,
    }

    print("[INFO] Loading model...")
    detector = QwenVulnDetector()
    print("[INFO] Model loaded. Running inference...")

    spinner()

    result = detector.infer(payload)
    print("\n=== ANALYSIS RESULT ===")
    print(result)

if __name__ == "__main__":
    main()
