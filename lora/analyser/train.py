# FIXED LoRA TRAINING SCRIPT — CUDA SAFE (QWEN 0.5B)
# Drop-in replacement for train_step1_lora.py

import os
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling,
)
from peft import LoraConfig, get_peft_model

# =========================
# BASIC CONFIG (QWEN 0.5B)
# =========================

MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"   # ✅ QWEN 0.5B
MAX_LENGTH = 1024          # safe on any GPU
BATCH_SIZE = 2             # 0.5B allows >1
GRAD_ACCUM = 4             # effective batch = 8
LR = 2e-4
EPOCHS = 1

# =========================
# LOAD DATA
# =========================

dataset = load_dataset("json", data_files="step1_dataset.jsonl", split="train")

# =========================
# TOKENIZER
# =========================

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME,
    use_fast=True,
    trust_remote_code=True,
)

if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token


def tokenize(example):
    return tokenizer(
        example["text"],
        truncation=True,
        max_length=MAX_LENGTH,
        padding=False,
    )
def format_example(example):
    for key in ["system", "instruction", "input", "output"]:
        if key not in example:
            raise ValueError(f"Missing key: {key} in {example}")

    prompt = (
        f"<|system|>\n{example['system']}\n"
        f"<|user|>\n{example['instruction']}\n{example['input']}\n"
        f"<|assistant|>\n"
    )

    full_text = prompt + example["output"]

    tokenized = tokenizer(
        full_text,
        truncation=True,
        max_length=MAX_LENGTH,
        padding="max_length"
    )

    tokenized["labels"] = tokenized["input_ids"].copy()
    return tokenized

dataset = dataset.map(format_example, remove_columns=dataset.column_names)
#
print(dataset.column_names)
print(dataset[0])


# =========================
# LOAD MODEL
# =========================

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    device_map="auto",
    torch_dtype=torch.float16,
    trust_remote_code=True,
)

model.config.use_cache = False

# =========================
# LORA CONFIG (QWEN)
# =========================

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=[
        "q_proj",
        "k_proj",
        "v_proj",
        "o_proj",
    ],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# =========================
# DATA COLLATOR
# =========================

data_collator = DataCollatorForLanguageModeling(
    tokenizer=tokenizer,
    mlm=False,
)

# =========================
# TRAINING ARGS
# =========================

training_args = TrainingArguments(
    output_dir="./lora-out",
    per_device_train_batch_size=BATCH_SIZE,
    gradient_accumulation_steps=GRAD_ACCUM,
    learning_rate=LR,
    num_train_epochs=EPOCHS,
    logging_steps=1,
    save_steps=500,
    save_total_limit=1,
    fp16=True,
    optim="adamw_torch",
    report_to="none",
    remove_unused_columns=False,
)

# =========================
# TRAINER
# =========================

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    data_collator=data_collator,
)

# =========================
# TRAIN
# =========================

trainer.train()

# =========================
# SAVE LORA
# =========================

model.save_pretrained("./lora-adapter")
tokenizer.save_pretrained("./lora-adapter")

print("\n✅ Qwen 0.5B LoRA training complete")

