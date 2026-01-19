from transformers import pipeline
import torch

device = "xpu" if torch.xpu.is_available() else "cpu"
print(f"Using device: {device}")

model_id = "NickyNicky/dolphin-2_6-phi-2_oasst2_chatML_V2"

pipe = pipeline("text-generation", model=model_id, device=device, trust_remote_code=True, max_length=50)

messages = [
    {"role": "user", "content": "What is pacific rim about?"},
]

response = pipe(messages)
print(response)