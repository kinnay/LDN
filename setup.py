
import setuptools

description = \
	"Python package for local wireless communication with a Nintendo Switch."

long_description = \
	"This package implements LDN, or local wireless communication " \
	"with a Nintendo Switch. Because LDN operates at the data link " \
	"layer it requires low-level access to your network hardware. " \
	"This package only supports Linux systems."

setuptools.setup(
	name = "ldn",
	version = "0.0.5",
	description = description,
	long_description = long_description,
	author = "Yannik Marchand",
	author_email = "ymarchand@me.com",
	url = "https://github.com/kinnay/LDN",
	license = "GPLv3",
	platforms = ["Linux"],
	packages = ["ldn"],
	install_requires = ["python-netlink", "pycryptodome"]
)
