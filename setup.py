"""
NEXUS SPECTER PRO — Setup
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="nexus-specter-pro",
    version="1.0.0",
    author="OPTIMIUM NEXUS LLC",
    author_email="contact@optimiumnexus.com",
    description="Military-Grade Automated Offensive Penetration Testing Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://www.optimiumnexus.com",
    project_urls={
        "Source":       "https://github.com/optimiumnexusllc/NEXUS-SPECTER-PRO",
        "Bug Reports":  "https://github.com/optimiumnexusllc/NEXUS-SPECTER-PRO/issues",
        "Company":      "https://www.optimiumnexus.com",
    },
    packages=find_packages(),
    python_requires=">=3.12",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "nsp=nsp_cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
    ],
    keywords="pentest penetration-testing red-team offensive-security cybersecurity",
)
