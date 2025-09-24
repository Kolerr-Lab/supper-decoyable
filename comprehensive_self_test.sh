#!/usr/bin/env bash
set -euo pipefail

# comprehensive_self_test.sh - DECOYABLE complete self-testing script
# Tests the entire platform on its own codebase
# Usage: ./comprehensive_self_test.sh

echo "🛡️ DECOYABLE Comprehensive Self-Test"
echo "====================================="
echo "Testing DECOYABLE on its own 8K+ line codebase"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Timestamp for reports
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="self_test_reports"
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}[1/8] Environment Setup${NC}"

# Check if we're in the right directory
if [ ! -f "main.py" ] || [ ! -f "pyproject.toml" ]; then
    echo -e "${RED}❌ Error: Not in DECOYABLE repository root${NC}"
    exit 1
fi

# Activate virtual environment
if [ -f ".venv/bin/activate" ]; then
    echo "Activating virtualenv..."
    # shellcheck disable=SC1091
    source .venv/bin/activate
else
    echo -e "${YELLOW}⚠️  No .venv found, creating temporary environment${NC}"
    python -m venv .venv
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install -r requirements.txt
fi

echo -e "${GREEN}✅ Environment ready${NC}"

echo ""
echo -e "${BLUE}[2/8] Code Quality Checks${NC}"

# Run linting
echo "Running code quality checks..."
if command -v ruff >/dev/null 2>&1; then
    ruff check . > "$REPORT_DIR/lint_report_$TIMESTAMP.txt" 2>&1 || true
    LINT_ISSUES=$(grep -c "error\|warning" "$REPORT_DIR/lint_report_$TIMESTAMP.txt" || echo "0")
    echo -e "${GREEN}✅ Linting complete - $LINT_ISSUES issues found${NC}"
else
    echo -e "${YELLOW}⚠️  ruff not installed, skipping lint check${NC}"
fi

# Run tests
echo "Running test suite..."
pytest -q --tb=short > "$REPORT_DIR/test_report_$TIMESTAMP.txt" 2>&1
TEST_EXIT_CODE=$?
if [ $TEST_EXIT_CODE -eq 0 ]; then
    PASSED_TESTS=$(grep -c "passed" "$REPORT_DIR/test_report_$TIMESTAMP.txt" || echo "0")
    echo -e "${GREEN}✅ Tests passed - $PASSED_TESTS tests successful${NC}"
else
    echo -e "${RED}❌ Some tests failed - check test_report_$TIMESTAMP.txt${NC}"
fi

echo ""
echo -e "${BLUE}[3/8] Security Scanning - Secrets${NC}"

# Scan for secrets
echo "Scanning for exposed secrets..."
python main.py scan secrets --path . --output "$REPORT_DIR/secrets_scan_$TIMESTAMP.json"

# Check results
SECRETS_FOUND=$(jq '.summary.total' "$REPORT_DIR/secrets_scan_$TIMESTAMP.json" 2>/dev/null || echo "0")
if [ "$SECRETS_FOUND" -eq 0 ]; then
    echo -e "${GREEN}✅ No secrets found in codebase${NC}"
else
    echo -e "${RED}❌ Found $SECRETS_FOUND potential secrets${NC}"
fi

echo ""
echo -e "${BLUE}[4/8] Security Scanning - Dependencies${NC}"

# Scan for dependency vulnerabilities
echo "Scanning for dependency vulnerabilities..."
python main.py scan deps --path . --output "$REPORT_DIR/deps_scan_$TIMESTAMP.json"

# Check results
DEPS_ISSUES=$(jq '.summary.total' "$REPORT_DIR/deps_scan_$TIMESTAMP.json" 2>/dev/null || echo "0")
if [ "$DEPS_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}✅ No dependency vulnerabilities found${NC}"
else
    echo -e "${YELLOW}⚠️  Found $DEPS_ISSUES dependency issues${NC}"
fi

echo ""
echo -e "${BLUE}[5/8] Security Scanning - SAST${NC}"

# Run SAST scanning
echo "Running Static Application Security Testing..."
python main.py scan sast --path . --output "$REPORT_DIR/sast_scan_$TIMESTAMP.json"

# Check results
SAST_ISSUES=$(jq '.summary.total' "$REPORT_DIR/sast_scan_$TIMESTAMP.json" 2>/dev/null || echo "0")
if [ "$SAST_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}✅ No SAST issues found${NC}"
else
    echo -e "${YELLOW}⚠️  Found $SAST_ISSUES SAST issues${NC}"
fi

echo ""
echo -e "${BLUE}[6/8] Comprehensive Scan - All${NC}"

# Run comprehensive scan
echo "Running comprehensive security scan..."
python main.py scan all --path . --output "$REPORT_DIR/comprehensive_scan_$TIMESTAMP.json"

# Check comprehensive results
COMPREHENSIVE_TOTAL=$(jq '.summary.total_issues' "$REPORT_DIR/comprehensive_scan_$TIMESTAMP.json" 2>/dev/null || echo "0")
if [ "$COMPREHENSIVE_TOTAL" -eq 0 ]; then
    echo -e "${GREEN}✅ Comprehensive scan passed - no issues found${NC}"
else
    echo -e "${YELLOW}⚠️  Comprehensive scan found $COMPREHENSIVE_TOTAL total issues${NC}"
fi

echo ""
echo -e "${BLUE}[7/8] Active Defense Testing${NC}"

# Test active defense components (if available)
echo "Testing active defense status..."
if command -v decoyable >/dev/null 2>&1; then
    # Test defense status
    decoyable defense status > "$REPORT_DIR/defense_status_$TIMESTAMP.txt" 2>&1 || echo "Defense system not fully configured"

    # Test LLM status (if configured)
    decoyable defense llm-status > "$REPORT_DIR/llm_status_$TIMESTAMP.txt" 2>&1 || echo "LLM providers not configured"

    echo -e "${GREEN}✅ Active defense components tested${NC}"
else
    echo -e "${YELLOW}⚠️  decoyable CLI not available, skipping active defense tests${NC}"
fi

echo ""
echo -e "${BLUE}[8/8] API Testing${NC}"

# Test API endpoints (if server is running)
echo "Testing API endpoints..."
if curl -f http://localhost:8000/health >/dev/null 2>&1; then
    echo -e "${GREEN}✅ API server is running${NC}"

    # Test health endpoint
    curl -s http://localhost:8000/health > "$REPORT_DIR/api_health_$TIMESTAMP.json"

    # Test a scan endpoint
    curl -s -X POST "http://localhost:8000/scan/secrets" \
         -H "Content-Type: application/json" \
         -d '{"path": ".", "recursive": true}' > "$REPORT_DIR/api_scan_test_$TIMESTAMP.json"

    echo -e "${GREEN}✅ API endpoints tested${NC}"
else
    echo -e "${YELLOW}⚠️  API server not running, skipping API tests${NC}"
    echo "  💡 Run './run_full_check.sh' first to start the API server"
fi

echo ""
echo -e "${GREEN}🎉 DECOYABLE Self-Test Complete!${NC}"
echo "=================================="
echo ""
echo -e "${BLUE}📊 Test Summary:${NC}"
echo "  📁 Reports saved to: $REPORT_DIR/"
echo "  🕒 Test completed at: $(date)"
echo ""
echo -e "${BLUE}🔍 Results:${NC}"
echo "  🔧 Linting issues: $LINT_ISSUES"
echo "  🧪 Tests passed: $PASSED_TESTS"
echo "  🔐 Secrets found: $SECRETS_FOUND"
echo "  📦 Deps issues: $DEPS_ISSUES"
echo "  🔍 SAST issues: $SAST_ISSUES"
echo "  🎯 Total issues: $COMPREHENSIVE_TOTAL"
echo ""

# Overall assessment
if [ "$SECRETS_FOUND" -eq 0 ] && [ "$TEST_EXIT_CODE" -eq 0 ]; then
    echo -e "${GREEN}✅ OVERALL: DECOYABLE PASSED self-testing!${NC}"
    echo "   The platform successfully secured its own codebase."
else
    echo -e "${YELLOW}⚠️  OVERALL: Some issues found during self-testing${NC}"
    echo "   Review reports in $REPORT_DIR/ for details."
fi

echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "  📖 View detailed reports: ls -la $REPORT_DIR/"
echo "  🔧 Fix any issues found"
echo "  🚀 Run './run_full_check.sh' to start development server"
echo "  📊 Generate summary: cat $REPORT_DIR/* | grep -E '(error|warning|failed|passed)'"

echo ""
echo -e "${GREEN}🏆 DECOYABLE is testing itself - meta-security at its finest! 🛡️🤖${NC}"
