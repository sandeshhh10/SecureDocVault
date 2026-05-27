@echo off
REM ============================================================================
REM Secure-Doc Unit Test Runner — Windows Batch Script
REM ============================================================================
REM
REM Usage:
REM   run_tests.bat                  # Run all tests
REM   run_tests.bat -v               # Verbose output
REM   run_tests.bat -c               # With coverage report
REM
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================================
echo   Secure-Doc Unit Test Suite
echo ============================================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.10+ and add it to your PATH
    exit /b 1
)

REM Check for test file
if not exist tests.py (
    echo ERROR: tests.py not found in current directory
    exit /b 1
)

REM Parse arguments
set "mode=normal"
set "verbose="

:parse_args
if "%1"=="" goto run_tests
if "%1"=="-v" set "verbose=-v"
if "%1"=="--verbose" set "verbose=-v"
if "%1"=="-c" set "mode=coverage"
if "%1"=="--coverage" set "mode=coverage"
shift
goto parse_args

:run_tests
if "%mode%"=="coverage" (
    echo Running tests with coverage report...
    echo.
    python -m pytest tests.py --cov=tools --cov-report=html --cov-report=term-missing %verbose%
    if errorlevel 1 (
        echo.
        echo Tests FAILED!
        exit /b 1
    )
    echo.
    echo Coverage report generated in htmlcov/index.html
) else (
    echo Running tests...
    echo.
    if "%verbose%"=="-v" (
        python tests.py -v
    ) else (
        python tests.py
    )
    if errorlevel 1 (
        echo.
        echo Tests FAILED!
        exit /b 1
    )
)

echo.
echo ============================================================================
echo ✓ All tests PASSED
echo ============================================================================
echo.
exit /b 0
