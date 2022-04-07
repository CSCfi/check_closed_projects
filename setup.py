import setuptools
import os

requirements = list()
requirements_file = 'requirements.txt'
if os.access(requirements_file, os.R_OK):
    with open(requirements_file, 'r') as requirements_file_pointer:
        requirements = requirements_file_pointer.read().split()
setuptools.setup(
    scripts=['check_closed_projects/check_closed_projects.py'],
    author="Antonio J. Delgado",
    version='0.0.1',
    name='check_closed_projects',
    author_email="antonio.delgado@csc.fi",
    url="",
    description="",
    license="GPLv3",
    install_requires=requirements,
    #keywords=["my", "script", "does", "things"]
)
