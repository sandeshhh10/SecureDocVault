#!/bin/bash

# ============================================================================
# Secure-Doc Unit Test Runner — Unix/Linux/macOS Shell Script
# ============================================================================
#
# Usage:
#   ./run_tests.sh                  # Run all tests
#   ./run_tests.sh -v               # Verbose output
#   ./run_tests.sh -c               # With coverage report
#
# ============================================================================

set -e

echo ""
echo "============================================================================"
echo "  Secure-Doc Unit Test Suite"
echo "============================================================================"
echo ""

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo "ERROR: Python is not installed or not in PATH"
    echo "Please install Python 3.10+ and ensure it's in your PATH"
    exit 1
fi

# Check for test file
if [ ! -f tests.py ]; then
    echo "ERROR: tests.py not found in current directory"
    exit 1
fi

# Parse arguments
mode="normal"
verbose=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            verbose="-v"
            shift
            ;;
        -c|--coverage)
            mode="coverage"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-v|--verbose] [-c|--coverage]"
            exit 1
            ;;
    esac
done

# Run tests
if [ "$mode" = "coverage" ]; then
    echo "Running tests with coverage report..."
    echo ""
    if python -m pytest tests.py --cov=tools --cov-report=html --cov-report=term-missing $verbose; then
        echo ""
        echo "Coverage report generated in htmlcov/index.html"
    else
        echo ""
        echo "Tests FAILED!"
        exit 1
    fi
else
    echo "Running tests..."
    echo ""
    if [ -n "$verbose" ]; then
        python tests.py $verbose
    else
        python tests.py
    fi
    
    if [ $? -ne 0 ]; then
        echo ""
        echo "Tests FAILED!"
        exit 1
    fi
fi

echo ""
echo "============================================================================"
echo "✓ All tests PASSED"
echo "============================================================================"
echo ""
exit 0
