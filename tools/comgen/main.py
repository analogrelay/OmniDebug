import io
import os
import json
import optparse

import pcpp
import ipdb

from comgen.config import Configuration
from comgen.generator import ComGenerator

mapped_types = {
    'HRESULT': 'HResult',
    'BOOL': 'bool',
}

parser = optparse.OptionParser()
parser.add_option("--input-root", dest="input_root", default="", help="Root path for input files")
parser.add_option("--output-root", dest="output_root", default="", help="Root path for output files")

(options, args) = parser.parse_args()

if options.input_root == "":
    print("Please specify the root of the 'dotnet/runtime' repo with '--runtime-root'")
    exit(1)

if len(args) == 0:
    print("Please specify the config file path")
    exit(1)

input_root = os.path.abspath(options.input_root)
output_root = os.path.abspath(options.output_root or ".")
config_path = os.path.abspath(args[0])

with open(config_path, "r") as f:
    config = Configuration.from_json(json.load(f))

print(f"Generating COM Wrappers...")

# Set up the generator
gen = ComGenerator()

for key, value in config.mapped_types.items():
    gen.map_type(key, value)

# Walk all the files in the config
for file_entry in config.files:
    pp = pcpp.Preprocessor()
    for path in config.include_paths:
        pp.add_path(os.path.join(input_root, path))

    for value in config.defines:
        pp.define(value)

    print("Processing file: " + file_entry.source)
    source_path = os.path.join(input_root, file_entry.source)
    preprocessed = ""
    with open(source_path, "r") as f:
        contents = f.read()
        pp.parse(contents)
        f = io.StringIO()
        pp.write(oh=f)
        preprocessed = f.getvalue()

        if file_entry.ppout != "":
            with open(os.path.join(output_root, file_entry.ppout), "w") as f:
                f.write(preprocessed)
    
    if file_entry.enabled:
        # Walk the file parsing COM types, using Roots and Wrappers as needed.
        gen.walk(preprocessed, file_entry.source, file_entry.roots, config.clang_args)
        print("Processed file: " + file_entry.source)
    else:
        print("Skipped file: " + file_entry.source)

# Create output directory if it doesn't exist
if not os.path.exists(output_root):
    os.makedirs(output_root)

# Now we generate code
for file_entry in config.files:
    output_path = os.path.join(output_root, file_entry.target)
    with open(output_path, "w") as f:
        gen.write_file(f, file_entry.source)
        print("Wrote " + output_path)
for wrapper in config.wrappers:
    output_path = os.path.join(output_root, wrapper.target)
    with open(output_path, "w") as f:
        gen.write_wrapper(f, wrapper.name, wrapper.ifaces)
        print("Wrote " + output_path)