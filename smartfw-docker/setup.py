from setuptools import setup, find_packages

setup(
    name="smartfw",
    version="0.1.0",
    packages=find_packages,
    install_resources=[
        "scapy>=2.4.5",
        "scikit-learn>=1.0",
        "pandas>=1.3",
        "numpy>=1.21",
        "flask>=2.0",
        "joblib>=1.1",
    ],
    entry_points={"console_scripts": ["smartfw=cli:main"]},
    python_requires=">=3.8",
)