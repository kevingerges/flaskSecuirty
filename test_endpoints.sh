#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to check test result
check_test() {
    local expected_code=$1
    local actual_code=$2
    local test_name=$3
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$actual_code" -eq "$expected_code" ]; then
        echo -e "${GREEN}✓ PASSED${NC} - $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED${NC} - $test_name (Expected: $expected_code, Got: $actual_code)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Function to get CSRF token
get_csrf_token() {
    local url=$1
    local response=$(curl -s -c cookies.txt "$url")
    local csrf_token=$(echo "$response" | grep -oP 'name="csrf_token" type="hidden" value="\K[^"]+')
    if [ -z "$csrf_token" ]; then
        echo "Error: Could not extract CSRF token from page"
        exit 1
    fi
    echo "$csrf_token"
}
# Replace the get_csrf_token function with this macOS-compatible version
get_csrf_token() {
    local url=$1
    local response=$(curl -s -c cookies.txt "$url")
    local csrf_token=$(echo "$response" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
    if [ -z "$csrf_token" ]; then
        echo "Error: Could not extract CSRF token from page"
        return 1
    fi
    echo "$csrf_token"
}

# Add this function for rate limiting protection
wait_between_tests() {
    sleep 1  # Add 1 second delay between tests
}

# Add this before each test
wait_between_tests

# Modify the registration test to properly handle forms
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/register \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=testuser11" \
  --data-urlencode "password=TestPass123!@" \
  --data-urlencode "csrf_token=${CSRF_TOKEN}")

# Add proper form handling for login
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/login \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=testuser11" \
  --data-urlencode "password=TestPass123!@" \
  --data-urlencode "csrf_token=${CSRF_TOKEN}")

# Add proper form handling for transactions
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/manage \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "action=deposit" \
  --data-urlencode "amount=100" \
  --data-urlencode "csrf_token=${CSRF_TOKEN}")

echo -e "${BLUE}Starting Security Test Suite${NC}\n"

# 1. Registration Tests
echo -e "${YELLOW}=== Registration Tests ===${NC}"

echo "Fetching CSRF token for registration..."
CSRF_TOKEN=$(get_csrf_token "http://127.0.0.1:5000/register")
echo "Got CSRF token: ${CSRF_TOKEN:0:20}..."

# Valid Registration
CSRF_TOKEN=$(get_csrf_token "http://127.0.0.1:5000/register")
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/register \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser1&password=TestPass123!@&csrf_token=${CSRF_TOKEN}")


# Get new CSRF token for next request
CSRF_TOKEN=$(get_csrf_token "http://127.0.0.1:5000/register")

# Weak Password
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/register \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser2&password=weak&csrf_token=${CSRF_TOKEN}")
status_code=${response: -3}
check_test 400 $status_code "Weak Password Rejection"

# Get new CSRF token for next request
CSRF_TOKEN=$(get_csrf_token "http://127.0.0.1:5000/register")

# Duplicate Username
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/register \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser1&password=TestPass123!@&csrf_token=${CSRF_TOKEN}")
status_code=${response: -3}
check_test 400 $status_code "Duplicate Username Rejection"

# 2. Login Tests
echo -e "\n${YELLOW}=== Login Tests ===${NC}"

# Valid Login
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser1&password=TestPass123!@" \
  -c cookies.txt)
status_code=${response: -3}
check_test 302 $status_code "Valid Login"

# Invalid Password
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser1&password=wrongpass")
status_code=${response: -3}
check_test 401 $status_code "Invalid Password Rejection"

# Rate Limiting Check
echo -n "Testing rate limiting... "
for i in {1..6}; do
    response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/login \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=testuser1&password=wrongpass")
    status_code=${response: -3}
    if [ $i -eq 6 ] && [ "$status_code" -eq 429 ]; then
        check_test 429 $status_code "Rate Limiting"
        break
    fi
done

# 3. Protected Route Tests
echo -e "\n${YELLOW}=== Protected Route Tests ===${NC}"

# Dashboard with Token
response=$(curl -s -w "%{http_code}" -X GET http://127.0.0.1:5000/ \
  -b cookies.txt)
status_code=${response: -3}
check_test 200 $status_code "Dashboard Access with Token"

# Dashboard without Token
response=$(curl -s -w "%{http_code}" -X GET http://127.0.0.1:5000/)
status_code=${response: -3}
check_test 302 $status_code "Dashboard Access without Token"

# 4. Transaction Tests
echo -e "\n${YELLOW}=== Transaction Tests ===${NC}"

# Valid Deposit
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/manage \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=deposit&amount=100")
status_code=${response: -3}
check_test 302 $status_code "Valid Deposit"

# Valid Withdrawal
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/manage \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=withdraw&amount=50")
status_code=${response: -3}
check_test 302 $status_code "Valid Withdrawal"

# Insufficient Funds
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/manage \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=withdraw&amount=1000000")
status_code=${response: -3}
check_test 400 $status_code "Insufficient Funds Check"

# 5. Security Tests
echo -e "\n${YELLOW}=== Security Tests ===${NC}"

# SQL Injection Attempt
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin'--&password=anything")
status_code=${response: -3}
check_test 401 $status_code "SQL Injection Prevention"

# XSS Attempt
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=<script>alert(1)</script>&password=TestPass123!@")
status_code=${response: -3}
check_test 400 $status_code "XSS Prevention"

# CSRF Check
response=$(curl -s -w "%{http_code}" -X POST http://127.0.0.1:5000/manage \
  -b cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=deposit&amount=100" \
  -H "Origin: http://evil.com")
status_code=${response: -3}
check_test 403 $status_code "CSRF Protection"

# 6. Logout Tests
echo -e "\n${YELLOW}=== Logout Tests ===${NC}"

# Logout
response=$(curl -s -w "%{http_code}" -X GET http://127.0.0.1:5000/logout \
  -b cookies.txt)
status_code=${response: -3}
check_test 302 $status_code "Logout"

# Post-logout Access Attempt
response=$(curl -s -w "%{http_code}" -X GET http://127.0.0.1:5000/ \
  -b cookies.txt)
status_code=${response: -3}
check_test 302 $status_code "Post-logout Protection"

# Print Summary
echo -e "\n${BLUE}=== Test Summary ===${NC}"
echo -e "Total Tests: ${YELLOW}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

# Cleanup
rm -f cookies.txt

# Exit with status code based on test results
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed successfully!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed. Please check the output above.${NC}"
    exit 1
fi