"""Package configuration."""
import setuptools

setuptools.setup(
    author="Jonathan Bowman",
    description="Bulk query client for Salesforce.",
    entry_points={"console_scripts": ["sfbulkquery=sfbulkquery:run"]},
    name="sfbulkquery",
    py_modules=["sfbulkquery"],
    version="0.1.0",
)
