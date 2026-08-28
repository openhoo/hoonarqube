import tarfile

archive = tarfile.open("bundle.tar")
archive.extractall()
