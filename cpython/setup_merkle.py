from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

examples_extension = Extension(
    name="pymerkle",
    sources=["merkletree.pyx"],
    libraries=["evercrypt.host"],
    library_dirs=["/home/jumaffre/playground/cpython"],
    include_dirs=["/home/jumaffre/playground/cpython/evercrypt/kremlin", "/home/jumaffre/playground/cpython/evercrypt/kremlin/kremlib"]
)

setup(
    name="pymerkle",
    ext_modules=cythonize([examples_extension])
)