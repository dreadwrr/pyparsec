from setuptools import setup, Extension
 
module = Extension(
    'mftparser.mftparser',
    sources=['parsec.c', 'parseclib.c'],
    py_limited_api=True,
    define_macros=[
        ('Py_LIMITED_API', '0x03090000'),
        ('_CRT_SECURE_NO_WARNINGS', '1'),
    ],
)

setup(
    name='mftparser',
    version='0.1.3',
    packages=['mftparser'],
    options={'bdist_wheel': {'py_limited_api': 'cp39'}},
    ext_modules=[module],
)
