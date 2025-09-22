#!/usr/bin/env python3
"""
Quick test script to validate DECOYABLE API functionality
"""
import subprocess
import time
import requests
import sys
import os

def test_api():
    """Test the DECOYABLE API server"""
    print("🧪 Testing DECOYABLE API Server...")

    # Start the server in background
    print("Starting API server...")
    server_process = subprocess.Popen([
        sys.executable, "decoyable/api/app.py",
        "--host", "127.0.0.1",
        "--port", "8003"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for server to start
    time.sleep(3)

    try:
        # Test health endpoint
        print("Testing health endpoint...")
        response = requests.get("http://127.0.0.1:8003/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health endpoint responding")
            print(f"Response: {response.json()}")
        else:
            print(f"❌ Health endpoint failed: {response.status_code}")

        # Test scan endpoint
        print("Testing scan endpoint...")
        test_data = {"path": "."}
        response = requests.post("http://127.0.0.1:8003/scan", json=test_data, timeout=10)
        if response.status_code in [200, 202]:
            print("✅ Scan endpoint responding")
        else:
            print(f"❌ Scan endpoint failed: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"❌ API request failed: {e}")
    finally:
        # Clean up
        print("Stopping server...")
        server_process.terminate()
        server_process.wait()

    print("🎉 API test completed!")

if __name__ == "__main__":
    test_api()