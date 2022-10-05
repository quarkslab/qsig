import setuptools

setuptools.setup(
    name="qsig",
    version="0.0.1",
    author='Alexis "dm" Challande',
    author_email="achallande@quarkslab.com",
    description="Signature generator and detector",
    packages=setuptools.find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    python_requires=">=3.9",
    extra_require={
        "doc": ["mkdocs", "mkdocs-material", "mkdocstrings"],
    }
)
