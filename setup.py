from setuptools import setup, Extension
 
module = Extension(
    'mftparser',
    sources=['parser.c', 'parserlib.c'],
    py_limited_api=True,
    define_macros=[('Py_LIMITED_API', '0x03090000')],
    extra_compile_args=['/D_CRT_SECURE_NO_WARNINGS'],
)

setup(
    name='mftparser',
    version='1.0',
    ext_modules=[module],
)
