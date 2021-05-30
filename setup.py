import setuptools

setuptools.setup(
    name='arrakis',
    version='0.0.1',
    packages=['grinventory',],
    license='MIT',
    description = 'A toolset for processing Grin Mimblewimble data structures',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author = 'Marek Narozniak',
    author_email = 'marek.yggdrasil@gmail.com',
    install_requires=[],
    url = 'https://github.com/marekyggdrasil/grinventory-py',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    package_data = {}
)
