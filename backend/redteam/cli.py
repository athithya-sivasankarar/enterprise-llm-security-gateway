import sys
import asyncio
import argparse
from backend.redteam.runner import run_security_validation_suite
from backend.redteam.reporter import format_text_report
from backend.redteam.categories import TestCategory


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enterprise LLM Security Gateway — Automated Security Validation & Red-Team CLI"
    )
    parser.add_argument(
        "--category", "-c",
        type=str,
        help=f"Filter test execution by category (Options: {', '.join(c.value for c in TestCategory)})",
        default=None
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Print detailed execution report (always printed by default in CLI)"
    )
    return parser.parse_args()


async def async_main():
    args = parse_args()
    categories = [args.category.upper()] if args.category else None

    print("\n[+] Starting Enterprise Security Gateway Validation Suite...")
    if categories:
        print(f"[+] Filtering categories: {', '.join(categories)}")
    else:
        print("[+] Running full safe validation suite across all 14 categories...")

    report = await run_security_validation_suite(
        categories=categories,
        created_by="cli-user"
    )

    print("\n" + format_text_report(report) + "\n")

    if report.summary.get("failed_tests", 0) > 0 or report.summary.get("error_tests", 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
