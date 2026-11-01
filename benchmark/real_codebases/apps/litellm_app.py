import litellm

try:
    litellm.completion(model="gpt-4o-mini", api_key="sk-test-not-a-real-key", messages=[
        {"role": "user", "content": "Refund rahul.k@example.com, card 4111 1111 1111 1111, phone +91 98765 43210"}])
except Exception as e:  # stub mode answers {}, so the call is expected to fail
    print("litellm ended:", type(e).__name__, str(e)[:200])
