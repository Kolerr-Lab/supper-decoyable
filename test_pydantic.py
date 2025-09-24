import os

os.environ["TEST_VAR"] = "hello"
from pydantic import Field
from pydantic_settings import BaseSettings


class TestSettings(BaseSettings):
    test_var: str = Field(default="default")


s = TestSettings()
print("test_var:", s.test_var)
