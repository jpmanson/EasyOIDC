import setuptools
from pathlib import Path

README = (Path(__file__).parent/"README.md").read_text()

setuptools.setup(
    name="EasyOIDC",
    version="0.1.1",
    author="Juan Pablo Manson",
    author_email="jpmanson@gmail.com",
    description="Easy integration with OIDC authentication servers",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/jpmanson/EasyOIDC",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[],
    python_requires=">=3.9",
    license_files=("LICENSE",),
    install_requires=[
        "Authlib>=1.3.0",
        "requests>=2.31.0",
        "python-decouple>=3.8",
        "redis_collections>=0.12.0",
    ],
)