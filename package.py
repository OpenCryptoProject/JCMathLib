import os
import re

from argparse import ArgumentParser

DIR = "./applet/src/main/java/opencrypto/jcmathlib/"

CURVES = {"SecP256r1", "SecP256k1", "SecP512r1"}
FILTERED_FILES = {"UnitTests.java", "ECExample.java", "Integer.java"}


def load_imports(files):
    imports = set()
    for file in files:
        with open(file, "r") as f:
            for line in f:
                if re.search(r"import .*;", line):
                    imports.add(line.strip())

    # Remove all imports that are already imported by a wildcard
    imports_copy = imports.copy()
    for imp in filter(lambda x: "*;" in x, imports_copy):
        for other in imports_copy:
            if other != imp and other.startswith(imp[:-2]):
                imports.remove(other)
    return imports


def package_file(file, keep_locks=False):
    lines = []
    skip = False
    with open(file, "r") as f:
        for line in f:
            if "[DependencyEnd:ObjectLocker]" in line:
                skip = False
                continue
            if not keep_locks and "[DependencyBegin:ObjectLocker]" in line:
                skip = True
            if skip:
                continue
            if re.search(r"import .*;", line) or re.search(r"package .*;", line):
                continue
            if not keep_locks and re.search(r"\.(un)?lock\(.*\)", line) or re.search(r"registerLock\(", line):
                continue
            lines.append(
                ("    " + line.replace("public class ", "public static class ")).rstrip())

    # Remove empty starting and last lines
    while lines[0].strip() == "":
        lines.pop(0)
    while lines[-1].strip() == "":
        lines.pop(-1)
    return os.linesep.join(lines)


def main():
    parser = ArgumentParser(
        prog="package.py",
        description="Package the JCMathLib library into a single file."
    )
    parser.add_argument(
        "-d", "--dir", help="Directory to package", default=DIR)
    parser.add_argument("-k", "--keep-locks", help="Keep locks",
                        action="store_true", default=False)
    parser.add_argument("-c", "--curves", help="Curves to include",
                        default=["SecP256k1"], nargs="+", choices=sorted(CURVES))
    parser.add_argument("-p", "--package",
                        help="Package name", default="your_package")
    parser.add_argument("-o", "--output", help="Output file",
                        default="jcmathlib.java")
    args = parser.parse_args()

    filtered_files = FILTERED_FILES.copy()
    if not args.keep_locks:
        filtered_files = filtered_files.union({"ObjectLocker.java"})
    included_files = sorted(map(
        lambda x: args.dir + x, filter(lambda x: x.endswith(".java") and x not in filtered_files, os.listdir(args.dir))))
    included_files += list(map(lambda x: f"{args.dir}curves/{x}.java", args.curves))

    imports = load_imports(included_files)

    with open(args.output, "w") as f:
        print("package " + args.package + ";", file=f)
        print(file=f)
        for imp in sorted(imports):
            print(imp, file=f)
        print(file=f)
        print("/**", file=f)
        print(" * Packaged JCMathLib library (https://github.com/OpenCryptoProject/JCMathLib).", file=f)
        print(" */", file=f)
        print("public class jcmathlib {", file=f)

        print((os.linesep * 2).join(map(lambda x: package_file(x,
              args.keep_locks), included_files)), file=f)

        print("}", file=f)


if __name__ == "__main__":
    main()
