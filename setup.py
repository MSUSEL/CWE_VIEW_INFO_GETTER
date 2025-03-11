from setuptools import setup, find_packages

setup(
    name='CWE_TOOLS',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[], # List any dependencies here
    entry_points={
        'console_scripts': [
            'my_command=my_package.my_module:main', # If you want a command-line tool
        ],
    },
)