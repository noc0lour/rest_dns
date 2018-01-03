from setuptools import setup

setup(
    name='rest_dns',
    packages=['rest_dns'],
    include_package_data=True,
    install_requires=[
        'flask',
        'flask-jwt',
        'pyyaml',
        'dnspython',
    ],
)
