import os
from setuptools import setup

# Read the contents of README.md for a long description (if available)
long_description = ""
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()

setup(
    name='ghostmap',
    version='1.0.0',
    description='GhostMap: Mapping the Digital Shadows',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='oslo-c4',
    author_email='oslo-c4@proton.me',
    py_modules=['ghostmap'],  # Assumes your main script is ghostmap.py
    python_requires='>=3.6',
    install_requires=[
        'requests>=2.20.0',  # Automatically installs requests if not present
    ],
    entry_points={
        'console_scripts': [
            'ghostmap=ghostmap:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
