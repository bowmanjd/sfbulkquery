"""Package configuration."""
import setuptools

setuptools.setup(
    author="Jonathan Bowman",
    description="Bulk query client for Salesforce.",
    entry_points={"console_scripts": ["sfbulk=sfbulk:run"]},
    name="sfbulk",
    py_modules=["sfbulk"],
    version="0.1.0",
)
