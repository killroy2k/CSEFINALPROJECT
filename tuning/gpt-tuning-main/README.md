# Fine-Tuning GPT-3.5 for Cyberthreat Detection

This project includes the necessary code and instructions to fine-tune OpenAI's GPT-3.5 model to detect cybersecurity threats based on NIST NVD CVE descriptions

## Prepare the Dataset

The dataset should be in JSONL format where each line represents a single training example. Each line should follow this structure:

```json
{"messages": [
  {"role": "system", "content": "Marv is a factual chatbot that is also sarcastic."},
  {"role": "user", "content": "What's the capital of France?"},
  {"role": "assistant", "content": "Paris, as if everyone doesn't know that already."}
]}
```

Roles:
- `system`: Specifies how GPT should act.
- `user`: Example of user input.
- `assistant`: Example of GPT's response.

Your dataset should contain at least 50 examples for GPT to learn efficiently.

## Tuning the Model

To fine-tune the model, follow these steps:

1. In `uploadandtune.py`, set your OpenAI API key on line 7.
2. On line 10, set the path to your training dataset.
3. Run `uploadandtune.py` to upload the dataset and start the training process.
4. Wait for the API to return the trained model ID (this may take several minutes).

Expected output will look like this:

```plaintext
file id is: file-4pxwZU7P2zwfWsg6XG35Rtkv
job id is: {
  "object": "fine_tuning.job",
  ... (additional output) ...
}
model is: ft:gpt-3.5-turbo-1106:personal::8MNmGPWm
```

## Using the Fine-Tuned Model in Your Project

To use the fine-tuned model, update the `check_if_threat` function in `project.py`:

1. Locate the `openai.ChatCompletion.create()` method (line 110).
2. Set the `model` parameter to your fine-tuned model ID.

Example:

```python
openai.ChatCompletion.create(
  model="ft:gpt-3.5-turbo-1106:personal::8MNmGPWm",
  ... (additional code) ...
)
```

## Reference

For detailed instructions on how to fine-tune GPT-3.5, visit the Pinecone tutorial: [Fine-Tuning GPT-3.5](https://www.pinecone.io/learn/fine-tune-gpt-3.5).
