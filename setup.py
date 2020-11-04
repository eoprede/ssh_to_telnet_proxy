import setuptools

with open("README.md", "r") as fd:
    long_description = fd.read()

setuptools.setup(
    name="ssh_to_telnet_proxy",
    version="0.1.2",
    description="SSH to telnet proxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/khornem/ssh_to_telnet_proxy",
    packages=['ssh_to_telnet_proxy'],
    entry_points = {
        'console_scripts': ['ssh_to_telnet_proxy=ssh_to_telnet_proxy.ssh_to_telnet_proxy:main'],
    },
    install_requires=[
        'paramiko',
        'gssapi'
    ],

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
