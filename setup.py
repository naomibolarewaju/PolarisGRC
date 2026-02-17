from setuptools import setup, find_packages

setup(
    name="polarisgrc-agent",
    version="1.0.0",
    description="PolarisGRC Security Audit Agent",
    author="Naomi",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "pyyaml>=6.0",
        "psutil>=5.9.0",
    ],
    entry_points={
        "console_scripts": [
            "polaris-agent=agent.cli:scan",
        ],
    },
    python_requires=">=3.11",
)
