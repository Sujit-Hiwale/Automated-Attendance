#!/usr/bin/env python3
"""
Test script for secure authentication backend
Tests all endpoints and security features
"""
import requests
import json
import time

BASE_URL = "http://localhost:5001/api"

def print_test(name, passed, details=""):
    """Print test result"""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} - {name}")
    if details:
        print(f"    {details}")
    print()

def test_health_check():
    """Test health check endpoint"""
    print("=" * 60)
    print("TEST 1: Health Check")
    print("=" * 60)
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        passed = response.status_code == 200
        print_test("Health Check", passed, f"Status: {response.status_code}")
        return passed
    except Exception as e:
        print_test("Health Check", False, str(e))
        return False

def test_registration():
    """Test user registration"""
    print("=" * 60)
    print("TEST 2: User Registration")
    print("=" * 60)
    
    # Test weak password
    weak_data = {
        "email": "admin@test.com",
        "password": "weak",
        "full_name": "Test Admin"
    }
    
    response = requests.post(f"{BASE_URL}/auth/register", json=weak_data)
    passed_weak = response.status_code == 400
    print_test("Weak Password Rejection", passed_weak, 
               f"Status: {response.status_code} - {response.json().get('error', '')}")
    
    # Test strong password
    strong_data = {
        "email": "admin@test.com",
        "password": "SecurePassword123!@#",
        "full_name": "Test Admin"
    }
    
    response = requests.post(f"{BASE_URL}/auth/register", json=strong_data)
    passed_strong = response.status_code == 201
    
    result = response.json()
    print_test("Strong Password Registration", passed_strong,
               f"Status: {response.status_code}")
    
    if passed_strong:
        print(f"    User ID: {result['user']['id']}")
        print(f"    Email: {result['user']['email']}")
        print(f"    Access Token: {result['access_token'][:30]}...")
        return result['access_token'], result['refresh_token']
    
    return None, None

def test_duplicate_registration():
    """Test duplicate email registration"""
    print("=" * 60)
    print("TEST 3: Duplicate Registration Prevention")
    print("=" * 60)
    
    data = {
        "email": "admin@test.com",
        "password": "SecurePassword123!@#",
        "full_name": "Duplicate Admin"
    }
    
    response = requests.post(f"{BASE_URL}/auth/register", json=data)
    passed = response.status_code == 409
    print_test("Duplicate Email Rejection", passed,
               f"Status: {response.status_code} - {response.json().get('error', '')}")
    
    return passed

def test_login_invalid():
    """Test login with invalid credentials"""
    print("=" * 60)
    print("TEST 4: Invalid Login")
    print("=" * 60)
    
    data = {
        "email": "admin@test.com",
        "password": "WrongPassword123!"
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=data)
    passed = response.status_code == 401
    
    result = response.json()
    print_test("Invalid Credentials Rejection", passed,
               f"Status: {response.status_code} - {result.get('message', '')}")
    
    if 'attempts_remaining' in result:
        print(f"    Attempts Remaining: {result['attempts_remaining']}")
    
    return passed

def test_login_valid():
    """Test login with valid credentials"""
    print("=" * 60)
    print("TEST 5: Valid Login")
    print("=" * 60)
    
    data = {
        "email": "admin@test.com",
        "password": "SecurePassword123!@#"
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=data)
    passed = response.status_code == 200
    
    result = response.json()
    print_test("Valid Login Success", passed,
               f"Status: {response.status_code}")
    
    if passed:
        print(f"    User ID: {result['user']['id']}")
        print(f"    Role: {result['user']['role']}")
        print(f"    Access Token: {result['access_token'][:30]}...")
        return result['access_token'], result['refresh_token']
    
    return None, None

def test_authenticated_endpoint(access_token):
    """Test accessing protected endpoint"""
    print("=" * 60)
    print("TEST 6: Protected Endpoint Access")
    print("=" * 60)
    
    # Without token
    response = requests.get(f"{BASE_URL}/auth/me")
    passed_no_token = response.status_code == 401
    print_test("No Token - Access Denied", passed_no_token,
               f"Status: {response.status_code}")
    
    # With token
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{BASE_URL}/auth/me", headers=headers)
    passed_with_token = response.status_code == 200
    
    if passed_with_token:
        result = response.json()
        print_test("With Token - Access Granted", passed_with_token,
                   f"User: {result['user']['email']}")
    else:
        print_test("With Token - Access Granted", passed_with_token,
                   f"Status: {response.status_code}")
    
    return passed_no_token and passed_with_token

def test_token_refresh(refresh_token):
    """Test token refresh"""
    print("=" * 60)
    print("TEST 7: Token Refresh")
    print("=" * 60)
    
    data = {"refresh_token": refresh_token}
    response = requests.post(f"{BASE_URL}/auth/refresh", json=data)
    passed = response.status_code == 200
    
    if passed:
        result = response.json()
        print_test("Token Refresh", passed,
                   f"New token: {result['access_token'][:30]}...")
        return result['access_token']
    else:
        print_test("Token Refresh", passed,
                   f"Status: {response.status_code}")
        return None

def test_rate_limiting():
    """Test rate limiting"""
    print("=" * 60)
    print("TEST 8: Rate Limiting")
    print("=" * 60)
    
    # Make multiple failed login attempts
    data = {
        "email": "ratelimit@test.com",
        "password": "WrongPassword123!"
    }
    
    print("Making 6 rapid failed login attempts...")
    for i in range(6):
        response = requests.post(f"{BASE_URL}/auth/login", json=data)
        print(f"    Attempt {i+1}: Status {response.status_code}")
        time.sleep(0.1)
    
    # Check if rate limited
    response = requests.post(f"{BASE_URL}/auth/login", json=data)
    passed = response.status_code == 429
    
    if passed:
        result = response.json()
        print_test("Rate Limiting Triggered", passed,
                   f"Locked for {result.get('locked_until', 0)} seconds")
    else:
        print_test("Rate Limiting Triggered", passed,
                   f"Expected 429, got {response.status_code}")
    
    return passed

def test_check_email():
    """Test email availability check"""
    print("=" * 60)
    print("TEST 9: Email Availability Check")
    print("=" * 60)
    
    # Check existing email
    response = requests.post(f"{BASE_URL}/auth/check-email",
                            json={"email": "admin@test.com"})
    passed_exists = response.status_code == 200 and response.json()['exists']
    print_test("Existing Email Check", passed_exists,
               f"Exists: {response.json().get('exists')}")
    
    # Check non-existing email
    response = requests.post(f"{BASE_URL}/auth/check-email",
                            json={"email": "newuser@test.com"})
    passed_not_exists = response.status_code == 200 and not response.json()['exists']
    print_test("Non-existing Email Check", passed_not_exists,
               f"Exists: {response.json().get('exists')}")
    
    return passed_exists and passed_not_exists

def test_logout(access_token):
    """Test logout"""
    print("=" * 60)
    print("TEST 10: Logout")
    print("=" * 60)
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(f"{BASE_URL}/auth/logout", headers=headers)
    passed = response.status_code == 200
    
    print_test("Logout", passed,
               f"Status: {response.status_code}")
    
    return passed

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("SECURE AUTHENTICATION BACKEND - TEST SUITE")
    print("=" * 60 + "\n")
    
    results = []
    
    # Test 1: Health Check
    results.append(test_health_check())
    
    # Test 2: Registration
    access_token, refresh_token = test_registration()
    results.append(access_token is not None)
    
    # Test 3: Duplicate Registration
    results.append(test_duplicate_registration())
    
    # Test 4: Invalid Login
    results.append(test_login_invalid())
    
    # Test 5: Valid Login
    access_token, refresh_token = test_login_valid()
    results.append(access_token is not None)
    
    if access_token:
        # Test 6: Protected Endpoint
        results.append(test_authenticated_endpoint(access_token))
        
        # Test 7: Token Refresh
        if refresh_token:
            new_token = test_token_refresh(refresh_token)
            results.append(new_token is not None)
            if new_token:
                access_token = new_token
        
        # Test 10: Logout
        results.append(test_logout(access_token))
    
    # Test 8: Rate Limiting (may take some time)
    results.append(test_rate_limiting())
    
    # Test 9: Email Check
    results.append(test_check_email())
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    percentage = (passed / total * 100) if total > 0 else 0
    
    print(f"Passed: {passed}/{total} ({percentage:.1f}%)")
    print("=" * 60 + "\n")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! The secure backend is working correctly.")
    else:
        print("⚠️  Some tests failed. Please review the output above.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Test suite error: {e}")
