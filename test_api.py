import requests
import json

BASE_URL = "http://localhost:5001"

print("Testing DLP Security System APIs...")
print("=" * 50)

# Test 1: Health Check
print("\n1. Testing Health Check API...")
try:
    response = requests.get(f"{BASE_URL}/api/health")
    if response.status_code == 200:
        print("✅ Health check passed!")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    else:
        print("❌ Health check failed!")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 2: Get Metrics
print("\n2. Testing Metrics API...")
try:
    response = requests.get(f"{BASE_URL}/api/metrics")
    if response.status_code == 200:
        print("✅ Metrics API working!")
        data = response.json()
        print(f"CPU Usage: {data.get('cpu_usage')}%")
        print(f"Memory Usage: {data.get('memory_usage')}%")
        print(f"Total Files Scanned: {data.get('total_files_scanned'):,}")
    else:
        print("❌ Metrics API failed!")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 3: Get Alerts
print("\n3. Testing Alerts API...")
try:
    response = requests.get(f"{BASE_URL}/api/alerts?limit=3")
    if response.status_code == 200:
        print("✅ Alerts API working!")
        data = response.json()
        print(f"Total alerts: {data.get('total')}")
    else:
        print("❌ Alerts API failed!")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 4: Generate Report (POST request)
print("\n4. Testing Report Generation API...")
try:
    payload = {
        "type": "daily",
        "format": "csv"
    }
    response = requests.post(f"{BASE_URL}/api/report/generate", 
                           json=payload,
                           headers={'Content-Type': 'application/json'})
    
    if response.status_code == 200:
        print("✅ Report generation working!")
        # Save the report
        with open("test_report.csv", "wb") as f:
            f.write(response.content)
        print("📄 Report saved as 'test_report.csv'")
    else:
        print(f"❌ Report generation failed! Status: {response.status_code}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 5: Scan History
print("\n5. Testing Scan History API...")
try:
    response = requests.get(f"{BASE_URL}/api/scan/history?limit=2")
    if response.status_code == 200:
        print("✅ Scan history API working!")
        scans = response.json()
        print(f"Retrieved {len(scans)} scans")
        for scan in scans:
            print(f"  - {scan.get('name')}: {scan.get('files_scanned')} files")
    else:
        print("❌ Scan history API failed!")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "=" * 50)
print("API Testing Complete!")
print("=" * 50)
