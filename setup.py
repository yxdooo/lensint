from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="lensint",
    version="2.0.0",
    author="Lensint Security Team",
    description="Advanced Image Forensics, AI Detection & Threat Intelligence Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Multimedia :: Graphics",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pillow>=10.0.0",
        "numpy>=1.24.0",
        "rich>=13.0.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.22.0",
        "python-multipart>=0.0.6",
    ],
    extras_require={
        "cv": ["opencv-python-headless>=4.8.0"],
    },
    entry_points={
        "console_scripts": [
            "lensint=lensint.cli:main",
        ],
    },
)
