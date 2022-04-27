from setuptools import setup

setup(
    name='Zscaler API Talkerse',
    version='1.5',
    author='Sergio Pereira',
    author_email='spereira@zscaler.com',
    packages=['/Users/spereira/github/zscaler_api_talkers'],
    url='https://github.com/sergitopereira/zscaler_api_talkers.git',
    license='LICENSE.txt',
    description='An awesome package that does something',
    long_description=open('README.md').read(),
    install_requires=[
        "python >= 3.7",
        "requests",
        "appdirs"
    ],
)
