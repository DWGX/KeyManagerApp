from setuptools import setup, find_packages

setup(
    name='main',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'numpy',
        'requests',
        'PySide6',
        'cryptography',
        "pyinstaller",
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    include_package_data=True,  # 包括非代码文件（例如图标）
)
