#!/usr/bin/env python3
"""Setup script for LENSINT framework.

Modern build configuration is maintained in pyproject.toml (PEP 517/621).
This file provides legacy compatibility with older pip/setuptools workflows.
"""
from setuptools import setup, find_packages

if __name__ == "__main__":
    setup(
        packages=find_packages(include=["lensint", "lensint.*"], exclude=["sample_images*", "docs*", "tests*"]),
        package_data={"lensint": ["web/**/*"]},
        include_package_data=True,
    )
