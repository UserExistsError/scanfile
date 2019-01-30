from setuptools import setup, find_packages
import scanfile

setup(
    name='scanfile',
    version='0.1.0',
    description='Scanner file parsing/manipulation',
    author='UserExistsError',
    packages=find_packages(include=['scanfile']),
    install_requires=[],
    python_requires='>=3.4',
    scripts=['scan-edit.py'],
)
