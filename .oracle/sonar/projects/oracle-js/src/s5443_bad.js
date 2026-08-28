fs.open(path, 'w', 0o777);
fs.writeFile(file, data, 511);
