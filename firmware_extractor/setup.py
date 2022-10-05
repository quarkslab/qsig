import setuptools

setuptools.setup(
    name="firmwareextractor",
    version="0.0.1",
    author='Alexis "dm" Challande',
    author_email="achallande@quarkslab.com",
    description="Firmware extractor module",
    packages=setuptools.find_packages(),
    install_requires=["python-magic", "lief"],
    python_requires=">=3.7",
)
