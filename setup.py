from setuptools import setup, find_packages

setup(
    name='zscaler_api_talkers',
    version='3.5',
    author='Sergio Pereira',
    author_email='sergitopereira@hotmail.com',
    packages=find_packages(),
    url='https://github.com/sergitopereira/zscaler_api_talkers.git',
    license='LICENSE.txt',
    description='Unofficial Zscaler API python SDK for ZIA, ZPA and ZCC',
    long_description_content_type="text/markdown",
    long_description=open('README.md').read(),
    install_requires=[
        "requests",
        "appdirs",
        "ipython"
    ],
)
