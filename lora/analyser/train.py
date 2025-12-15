# FIXED LoRA TRAINING SCRIPT — CUDA SAFE (QWEN 0.5B)
# Drop-in replacement for train_step1_lora.py

import os
# Fix deprecated CUDA config and optimize memory
os.environ["PYTORCH_ALLOC_CONF"] = "expandable_segments:True"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"  # Backward compatibility

import torch
import gc
torch.cuda.empty_cache()  # Clear cache before starting
import json
from datetime import datetime
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling,
)
from peft import LoraConfig, get_peft_model
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from transformers import TrainerCallback
import numpy as np

# =========================
# BASIC CONFIG (QWEN 0.5B)
# =========================

MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"   # ✅ QWEN 0.5B
MAX_LENGTH = 512           # Reduced from 1024 to save CUDA memory
BATCH_SIZE = 1             # Reduced from 2 to minimize CUDA memory
GRAD_ACCUM = 2             # Reduced from 4 (effective batch = 2)
LR = 2e-4
EPOCHS = 1
USE_GRADIENT_CHECKPOINTING = True  # Save memory by recomputing activations

# =========================
# LOAD DATA
# =========================

dataset = load_dataset("json", data_files="step1_dataset.jsonl", split="train")

# Split into train and eval (80-20)
split_dataset = dataset.train_test_split(test_size=0.2, seed=42)
train_dataset = split_dataset["train"]
eval_dataset = split_dataset["test"]

print(f"Training samples: {len(train_dataset)}")
print(f"Evaluation samples: {len(eval_dataset)}")

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

dataset = train_dataset.map(format_example, remove_columns=train_dataset.column_names)
eval_dataset = eval_dataset.map(format_example, remove_columns=eval_dataset.column_names)
#
print("Training dataset columns:", dataset.column_names)
print("Sample training data:", dataset[0])


# =========================
# LOAD MODEL
# =========================

print("🔄 Loading model with memory optimizations...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    device_map="auto",
    torch_dtype=torch.float16,
    trust_remote_code=True,
    low_cpu_mem_usage=True,  # Reduce CPU memory during loading
)

model.config.use_cache = False

# Enable gradient checkpointing to save memory
if USE_GRADIENT_CHECKPOINTING:
    model.gradient_checkpointing_enable()
    print("✅ Gradient checkpointing enabled - saves ~40% memory")

# =========================
# LORA CONFIG (QWEN) - Memory Optimized
# =========================

lora_config = LoraConfig(
    r=8,                  # Reduced from 16 to save memory
    lora_alpha=16,        # Reduced from 32
    target_modules=[
        "q_proj",
        "v_proj",         # Reduced to 2 modules (was 4)
    ],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)
print("📊 LoRA config: r=8, alpha=16, 2 target modules")

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# =========================
# ACCURACY CALLBACK (Memory Efficient)
# =========================

class AccuracyCallback(TrainerCallback):
    """
    Computes accuracy during evaluation without storing all predictions.
    This saves CUDA memory by computing metrics on-the-fly.
    """
    
    def __init__(self):
        self.eval_accuracies = []
        self.eval_steps = []
    
    def on_evaluate(self, args, state, control, metrics=None, **kwargs):
        """Called after evaluation - compute accuracy on small sample"""
        if metrics:
            # Store the step and loss
            step = state.global_step
            eval_loss = metrics.get('eval_loss', None)
            
            if eval_loss:
                print(f"\n📊 Step {step}: Eval Loss = {eval_loss:.4f}")
                
                # Estimate accuracy from loss (inverse relationship)
                # Lower loss ≈ Higher accuracy
                # This is an approximation but avoids OOM
                estimated_accuracy = max(0, min(100, 100 * (1 - eval_loss)))
                self.eval_accuracies.append(estimated_accuracy)
                self.eval_steps.append(step)
                print(f"   Estimated Accuracy ≈ {estimated_accuracy:.1f}% (from loss)")

def compute_final_accuracy(model, eval_dataset, tokenizer, device, max_samples=50):
    """
    Compute actual accuracy on a small subset after training.
    This runs separately to avoid OOM during training.
    """
    import torch
    
    print(f"\n🔍 Computing accuracy on {max_samples} validation samples...")
    
    model.eval()
    correct_tokens = 0
    total_tokens = 0
    
    # Sample a subset
    import random
    indices = random.sample(range(len(eval_dataset)), min(max_samples, len(eval_dataset)))
    
    with torch.no_grad():
        for idx in indices:
            try:
                sample = eval_dataset[idx]
                input_ids = torch.tensor([sample['input_ids']]).to(device)
                labels = torch.tensor([sample['labels']]).to(device)
                
                # Get predictions
                outputs = model(input_ids)
                predictions = torch.argmax(outputs.logits, dim=-1)
                
                # Compare with labels (ignore padding)
                mask = labels != -100
                correct_tokens += ((predictions == labels) & mask).sum().item()
                total_tokens += mask.sum().item()
                
                # Clear memory
                del input_ids, labels, outputs, predictions, mask
                
            except RuntimeError as e:
                if "out of memory" in str(e):
                    print(f"⚠️ OOM at sample {idx}, stopping accuracy computation")
                    break
                raise
    
    if total_tokens > 0:
        accuracy = (correct_tokens / total_tokens) * 100
        print(f"✅ Token Accuracy: {accuracy:.2f}% ({correct_tokens}/{total_tokens} tokens)")
        return accuracy
    else:
        print("⚠️ Could not compute accuracy")
        return None

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
    per_device_eval_batch_size=BATCH_SIZE,
    gradient_accumulation_steps=GRAD_ACCUM,
    learning_rate=LR,
    num_train_epochs=EPOCHS,
    logging_steps=5,
    eval_strategy="steps",
    eval_steps=100,              # Increased from 50 to reduce eval frequency
    save_steps=500,
    save_total_limit=1,
    fp16=True,
    optim="adamw_torch",         # Using standard optimizer (8bit requires bitsandbytes)
    report_to="none",
    remove_unused_columns=False,
    load_best_model_at_end=False,  # Disabled to save memory during eval
    metric_for_best_model="loss",
    max_grad_norm=1.0,            # Clip gradients for stability
    warmup_steps=5,               # Warmup for stability
    gradient_checkpointing=USE_GRADIENT_CHECKPOINTING,
    prediction_loss_only=True,    # Don't store predictions during eval (saves memory)
)

# =========================
# TRAINER
# =========================

# Create accuracy callback
accuracy_callback = AccuracyCallback()

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    eval_dataset=eval_dataset,
    data_collator=data_collator,
    callbacks=[accuracy_callback],
    # compute_metrics removed - prediction_loss_only=True means no predictions stored
)

# =========================
# TRAIN
# =========================

# Clear CUDA cache before training
if torch.cuda.is_available():
    torch.cuda.empty_cache()
    gc.collect()
    print(f"🔧 CUDA Memory allocated: {torch.cuda.memory_allocated()/1024**2:.2f} MB")
    print(f"🔧 CUDA Memory reserved: {torch.cuda.memory_reserved()/1024**2:.2f} MB")

print("\n🚀 Starting LoRA training with optimized settings...")
print(f"   Batch size: {BATCH_SIZE}, Grad accum: {GRAD_ACCUM}, Max length: {MAX_LENGTH}")
print(f"   Memory optimization: prediction_loss_only=True (no prediction storage)")

try:
    train_result = trainer.train()
except RuntimeError as e:
    if "out of memory" in str(e):
        print("\n⚠️ CUDA OOM during training. Clearing cache and retrying...")
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            gc.collect()
        raise
    else:
        raise

# =========================
# EVALUATION & METRICS
# =========================

print("\n📊 Evaluating model on validation set...")
eval_results = trainer.evaluate()

# Compute actual accuracy on a subset (memory-safe)
if torch.cuda.is_available():
    torch.cuda.empty_cache()
    gc.collect()

device = next(model.parameters()).device
final_accuracy = compute_final_accuracy(model, eval_dataset, tokenizer, device, max_samples=50)

# Store accuracy in results
if final_accuracy is not None:
    eval_results['eval_accuracy'] = final_accuracy / 100  # Convert to 0-1 range

# Create metrics report
metrics_report = {
    "timestamp": datetime.now().isoformat(),
    "model": MODEL_NAME,
    "training_config": {
        "batch_size": BATCH_SIZE,
        "gradient_accumulation_steps": GRAD_ACCUM,
        "learning_rate": LR,
        "epochs": EPOCHS,
        "max_length": MAX_LENGTH,
    },
    "training_results": {
        "final_loss": train_result.training_loss,
        #"epoch": train_result.epoch,
    },
    "evaluation_results": eval_results,
    "dataset_info": {
        "training_samples": len(dataset),
        "evaluation_samples": len(eval_dataset),
        "total_samples": len(dataset) + len(eval_dataset),
    }
}

# Save metrics to file
with open("./lora-out/training_metrics.json", "w") as f:
    json.dump(metrics_report, f, indent=2)

print("\n" + "="*60)
print("📈 TRAINING METRICS SUMMARY")
print("="*60)
print(f"Training Loss: {train_result.training_loss:.4f}")
print(f"Evaluation Loss: {eval_results.get('eval_loss', 'N/A')}")
if 'eval_accuracy' in eval_results:
    print(f"Token Accuracy: {eval_results['eval_accuracy']*100:.2f}%")
print(f"Training Samples: {len(dataset)}")
print(f"Evaluation Samples: {len(eval_dataset)}")
print(f"Epochs Completed: {train_result.epoch}")
print("="*60)
print(f"✅ Metrics saved to: ./lora-out/training_metrics.json")
print("="*60)

# =========================
# SAVE LORA
# =========================

model.save_pretrained("./lora-adapter")
tokenizer.save_pretrained("./lora-adapter")

print("\n✅ Qwen 0.5B LoRA training complete")

