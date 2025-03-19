from setuptools import setup

setup(
    name='ghostmap',
    version='1.0.0',
    description='GhostMap: Mapping the Digital Shadows',
    author='Your Name',
    author_email='youremail@example.com',
    py_modules=['ghostmap'],  # assumes your main script is ghostmap.py
    install_requires=[
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'ghostmap=ghostmap:main',
        ],
    },
)
