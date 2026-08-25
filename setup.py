from setuptools import setup, find_packages

setup(
    name="mugiwara",
    version="0.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "typer>=0.12.0",
        "rich>=13.7.0",
        "pydantic>=2.7.0",
        "pydantic-settings>=2.2.0",
        "pyyaml>=6.0.1",
        "docker>=7.0.0",
    ],
    extras_require={
        "cloud": [
            "fastapi>=0.115.0",
            "uvicorn>=0.30.0",
            "httpx>=0.27.0",
            "pyjwt[crypto]>=2.9.0",
            "psycopg[binary,pool]>=3.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mugiwara-cloud-api=mugiwara.cloud.api:main",
            "mugiwara-cloud-worker=mugiwara.cloud.worker:main",
        ],
    },
    python_requires=">=3.10",
)
