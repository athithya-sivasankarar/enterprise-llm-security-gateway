import pytest
import re
from backend.redteam.catalog import TEST_CATALOG, get_test_catalog, get_test_by_id
from backend.redteam.categories import TestCategory, SeverityLevel


def test_catalog_non_empty_and_valid():
    """Verify that the test catalog contains tests for all required security categories."""
    assert len(TEST_CATALOG) >= 14
    
    # Verify all 14 categories are represented
    catalog_categories = {t.category for t in TEST_CATALOG}
    for cat in TestCategory:
        assert cat in catalog_categories, f"Category {cat.value} missing from catalog"


def test_catalog_unique_test_ids():
    """Ensure every test in the catalog has a unique test_id."""
    test_ids = [t.test_id for t in TEST_CATALOG]
    assert len(test_ids) == len(set(test_ids)), "Duplicate test IDs found in catalog"


def test_catalog_safe_synthetic_data_only():
    """Verify that test definitions do not contain real API keys or sensitive production data."""
    forbidden_patterns = [
        r"\bAKIA[0-9A-Z]{16}\b(?!IOSFODNN7EXAMPLE)", # Real AWS key check (excluding AWS synthetic documentation example)
        r"sk-[a-zA-Z0-9]{32,}",                      # Real OpenAI key length
    ]
    
    for t in TEST_CATALOG:
        payload_str = str(t.model_dump())
        assert t.model in ("mock-model", "gpt-4o"), f"Test {t.test_id} uses unexpected model"
        for pattern in forbidden_patterns:
            matches = re.findall(pattern, payload_str)
            assert len(matches) == 0, f"Test {t.test_id} appears to contain real credentials: {matches}"


def test_catalog_category_filtering():
    """Test get_test_catalog with category filtering."""
    dlp_tests = get_test_catalog(["INPUT_DLP"])
    assert len(dlp_tests) >= 4
    for t in dlp_tests:
        assert t.category == TestCategory.INPUT_DLP

    multi_tests = get_test_catalog(["INPUT_DLP", "AUTHENTICATION"])
    assert len(multi_tests) >= 7
    for t in multi_tests:
        assert t.category in (TestCategory.INPUT_DLP, TestCategory.AUTHENTICATION)


def test_get_test_by_id():
    """Test lookup of individual test cases by ID."""
    test_auth = get_test_by_id("AUTH-001")
    assert test_auth is not None
    assert test_auth.name == "Missing API Key Authentication Rejection"
    assert test_auth.expected_status == 401

    test_nonexistent = get_test_by_id("INVALID-ID-999")
    assert test_nonexistent is None
