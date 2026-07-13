"""
Test script to demonstrate GitHub API rate limit handling.
This simulates what happens when the rate limit is exceeded.
"""
import requests

# Test WITHOUT authentication (will hit rate limit quickly)
def test_unauthenticated_rate_limit():
    print("Testing unauthenticated GitHub API (should hit rate limit)...")

    headers = {
        "User-Agent": "test-rate-limit/1.0"
    }

    query = '{ viewer { login } }'

    try:
        resp = requests.post(
            'https://api.github.com/graphql',
            headers=headers,
            json={'query': query},
            timeout=10
        )

        print(f"Status: {resp.status_code}")

        if resp.status_code in [403, 429]:
            try:
                error_body = resp.json()
                error_msg = error_body.get("message", resp.text[:200])
            except Exception:
                error_msg = resp.text[:200]

            print(f"[WARN] GitHub API error (HTTP {resp.status_code}): {error_msg}")

            # This is the format we now use in the codebase
            if "rate limit" in error_msg.lower():
                print("\n[SUCCESS] Rate limit message correctly logged!")
        else:
            print(f"Response: {resp.text[:200]}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_unauthenticated_rate_limit()
