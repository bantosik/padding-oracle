from setuptools import setup

setup(name='padding_oracle',
	version='0.1',
	description='Package contains padding oracle attack for authenticated encryption schemes using MAC-then-encrypt mode',
	author='Bartlomiej Antosik',
	author_email='antosik.bartek@gmail.com',
	license='BSD',
	packages=['padding_oracle'],
	install_requires=['crypto_primitives',],
	zip_safe=False)

