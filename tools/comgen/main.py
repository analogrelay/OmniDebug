import io
import os
import optparse
import json
import pprint

import ipdb
import pcpp
import clang.cindex

parser = optparse.OptionParser()
parser.add_option("--runtime-root", dest="runtime_root", default="", help="Path to the runtime root")

(options, args) = parser.parse_args()

if options.runtime_root == "":
    print("Please specify the root of the 'dotnet/runtime' repo with '--runtime-root'")
    exit(1)

runtime_root = os.path.abspath(options.runtime_root)

print(f"Generating COM Wrappers for ICorDebug located at {runtime_root}...")

pp = pcpp.Preprocessor()
pp.add_path(os.path.join(runtime_root, "src/coreclr/pal/inc/rt"))
pp.add_path(os.path.join(runtime_root, "src/coreclr/pal/inc"))
pp.define("COM_NO_WINDOWS_H")
pp.define("__linux__")
pp.define("__x86_64__")
pp.define("BEGIN_INTERFACE")
pp.define("END_INTERFACE")
pp.define("_COM_Outptr_")

# Load the input file
input_file = os.path.join(runtime_root, "src/coreclr/pal/prebuilt/inc/cordebug.h")
processed = ""
with open(input_file, "r") as f:
    input_file_contents = f.read()
    pp.parse(input_file_contents)
    f = io.StringIO()
    pp.write(oh=f)
    processed = f.getvalue()

class ComMethod():
    def __init__(self, name, return_type, parameters):
        self.name = name
        self.return_type = return_type
        self.parameters = parameters

    def generate(f, generator):
        if f.kind != clang.cindex.CursorKind.FIELD_DECL or f.type.kind != clang.cindex.TypeKind.POINTER:
            raise "Invalid field type"
        
        typ = f.type.get_pointee()

        if typ.kind != clang.cindex.TypeKind.FUNCTIONPROTO:
            raise "Invalid field type"

        ret_type = generator.resolve_type(typ.get_result())
        params = [ (param.displayname, generator.resolve_type(param.type)) for param in f.get_children() if param.kind == clang.cindex.CursorKind.PARM_DECL ]
        return ComMethod(f.displayname, ret_type, params)

class ComInterface():
    def __init__(self):
        self.name = ""
        self.methods = []
    
    def define(self, cursor, generator):
        self.name = cursor.displayname
        self.methods = [ComMethod.generate(f, generator) for f in cursor.type.get_fields()]

class ComStruct():
    def __init__(self):
        self.name = ""
        self.methods = []
    
    def define(self, cursor, generator):
        self.name = cursor.displayname
        pass

class ComGenerator():
    root_names = []
    types = {}
    idx = clang.cindex.Index.create()

    def add_root(self, name):
        self.root_names.append(name)

    def walk(self, content):
        tu = self.idx.parse('cordebug.h', unsaved_files=[('cordebug.h', content)])

        for cursor in tu.cursor.get_children():
            if cursor.kind == clang.cindex.CursorKind.STRUCT_DECL and cursor.displayname in self.root_names:
                self.resolve_type(cursor.type)

    def generate_type(self, cursor):
        if cursor.kind == clang.cindex.CursorKind.STRUCT_DECL and cursor.displayname.endswith("Vtbl"):
            return ComInterface.generate(cursor, self)
        ipdb.set_trace()

    def resolve_type(self, t):
        t = t.get_canonical()
        if t.kind == clang.cindex.TypeKind.POINTER:
            inner = self.resolve_type(t.get_pointee())
            return f"{inner}*"
        elif t.kind == clang.cindex.TypeKind.RECORD:
            rec = self.resolve_record(t)
            return rec.name
        elif t.kind == clang.cindex.TypeKind.ENUM:
            return t.get_declaration().displayname
        elif t.kind == clang.cindex.TypeKind.INT:
            return "int"
        elif t.kind == clang.cindex.TypeKind.UINT:
            return "uint"
        elif t.kind == clang.cindex.TypeKind.VOID:
            return "void"
        else:
            ipdb.set_trace()
            return "Unknown type"

    def resolve_record(self, typ):
        decl = typ.get_declaration()
        name = decl.displayname.replace("Vtbl", "") if decl.kind == clang.cindex.CursorKind.STRUCT_DECL and decl.displayname.endswith("Vtbl") else decl.displayname
        if name in self.types:
            return self.types[name]
        else:
            if decl.kind == clang.cindex.CursorKind.STRUCT_DECL and decl.displayname.endswith("Vtbl"):
                iface = ComInterface()
                self.types[name] = iface
                iface.define(decl, self)
                return iface
            elif decl.kind == clang.cindex.CursorKind.STRUCT_DECL:
                struct = ComStruct()
                self.types[name] = struct
                struct.define(decl, self)
                return struct

gen = ComGenerator()
gen.add_root("ICorDebugVtbl")
gen.walk(processed)

print(gen.types)

                # for field in vtbl.get_children():
                #     name = field.displayname
                #     type = field.type.get_canonical()
                #     func = type.get_pointee()
                #     ret_type = self.map_csharp_type(func.get_result().get_canonical())
                #     args = [ self.map_csharp_type(t) for t in func.argument_types() ]
                #     print(f"    {ret_type} {name}({', '.join(args)});")