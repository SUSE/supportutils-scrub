from setuptools import setup, find_packages
import os
import re

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def get_version():
    main_py = os.path.join(os.path.dirname(__file__), 'src', 'supportutils_scrub', 'main.py')
    with open(main_py) as f:
        match = re.search(r'SCRIPT_VERSION\s*=\s*["\']([^"\']+)', f.read())
    return match.group(1)

setup(
    name='supportutils-scrub',
    version=get_version(),
    description='Utility to sanitize and remove sensitive data from supportconfig tarballs',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    author='Ronald Pina',
    author_email='rpina@suse.com',
    url='https://github.com/opensuse/supportutils-scrub',
    license='GPL-2.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'supportutils-scrub=supportutils_scrub.main:main',
        ],
    },
    data_files=[
        ('/etc/supportutils-scrub', ['config/supportutils-scrub.conf']),
        ('/usr/share/man/man8', ['man/supportutils-scrub.8']),
        ('/usr/share/man/man5', ['man/supportutils-scrub.conf.5']),
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)

