"""Package configuration."""
import setuptools

setuptools.setup(
    author="Jonathan Bowman",
    description="Bulk query client for Salesforce.",
    entry_points={"console_scripts": ["sfquery=sfquery:run"]},
    name="sfquery",
    py_modules=["sfquery"],
    version="0.1.0",
)
