import io
import os
import optparse

import pcpp
import ipdb
import clang.cindex

reserved_words = ['string']

mapped_types = {
    'HRESULT': 'HResult',
    'BOOL': 'bool',
}

def escape_name(name):
    if name in reserved_words:
        return '@' + name
    return name

class ComWrapper():
    """
    Represents a class that can be inherited from to implement a set of COM interfaces.
    """
    def __init__(self, name, ifaces):
        self.name = name
        self.ifaces = ifaces
    
    def write(self, f, indent):
        f.write(f"{indent}unsafe abstract class {self.name}: COMCallableIUnknown\n")
        f.write(indent + "{\n")
        for iface in self.ifaces:
            f.write(indent + "    public " + iface.basename + "Ptr " + iface.name + " { get; }\n")
        f.write("\n")
        f.write(indent + f"    public {self.name}()\n")
        f.write(indent + "    {\n")
        for iface in self.ifaces:
            f.write(indent + f"        {iface.name} = Define{iface.name}(this, InterfaceIds.{iface.name});\n")
        f.write(indent + "    }\n")
        f.write("\n")
        for iface in self.ifaces:
            for method in iface.methods:
                f.write(indent + f"    protected virtual {method.return_type} {method.name}(")
                for i, (name, type) in enumerate(method.parameters):
                    if i > 0:
                        f.write(", ")
                    f.write(f"{type} {name}")
                f.write(")\n")
                f.write(indent + "    {\n")
                f.write(indent + "        return HResult.E_NOTIMPL;\n")
                f.write(indent + "    }\n")
                f.write("\n")
        for iface in self.ifaces:
            f.write(indent + f"    static {iface.basename}Ptr Define{iface.name}({self.name} self, Guid iid)\n")
            f.write(indent + "    {\n")
            f.write(indent + "        var builder = self.AddInterface(iid, validate: false);\n")
            for method in iface.methods:
                f.write(indent + f"        builder.AddMethod(new {iface.name}Delegates.{method.name}Delegate((_")
                for (name, _) in method.parameters:
                    f.write(", " + name)
                f.write(f") => self.{method.name}(")
                for i, (name, _) in enumerate(method.parameters):
                    if i != 0:
                        f.write(", ")
                    f.write(name)
                f.write(")));\n")
            f.write(indent + f"        return new {iface.basename}Ptr(builder.Complete());\n")
            f.write(indent + "    }\n")
            f.write("\n")

        for iface in self.ifaces:
            f.write(indent + f"    static class {iface.name}Delegates\n")
            f.write(indent + "    {\n")
            for method in iface.methods:
                f.write(indent + "        [UnmanagedFunctionPointer(CallingConvention.Winapi)]\n")
                f.write(indent + f"        public delegate {method.return_type} {method.name}Delegate(IntPtr self")
                for i, (name, type) in enumerate(method.parameters):
                    f.write(f", {type} {name}")
                f.write(");\n")
                f.write("\n")
            f.write(indent + "    }\n")
            f.write("\n")
        f.write(indent + "}\n")

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
        children = iter(f.get_children())
        next(children) # Skip the return type
        next(children) # Skip the "This" parameter
        
        params = [ (param.displayname, generator.resolve_type(param.type)) for param in children if param.kind == clang.cindex.CursorKind.PARM_DECL ]
        return ComMethod(f.displayname, ret_type, params)

    def write_impl(self, f, indent):
        f.write(indent + f"public {self.return_type} {escape_name(self.name)}(")
        for i, (name, type) in enumerate(self.parameters):
            if i != 0:
                f.write(", ")
            f.write(f"{type} {escape_name(name)}")
        f.write(")\n")
        f.write(indent + f"    => VTable.{self.name}Ptr(Self")
        for i, (name, type) in enumerate(self.parameters):
            f.write(", ")
            if type.startswith("ref "):
                f.write("ref ")
            f.write(f"{escape_name(name)}")
        f.write(");\n")
        f.write("\n")

    def write_ptr(self, f, indent):
        f.write(indent + f"public readonly delegate* unmanaged[Stdcall]<IntPtr, ")
        for i, (_, type) in enumerate(self.parameters):
            f.write(f"{type}, ")
        f.write(f"{self.return_type}> {self.name}Ptr;\n")

class ComInterface():
    def __init__(self):
        self.name = ""
        self.basename = ""
        self.methods = []
    
    def define(self, cursor, generator, name):
        self.name = cursor.displayname.replace("Vtbl", "")
        self.basename = self.name[1:]
        if self.name == "" or self.name is None:
            self.name = name
        self.methods = [
            ComMethod.generate(f, generator) 
            for f in cursor.type.get_fields()
            # Skip the IUnknown methods
            if f.displayname not in ["QueryInterface", "AddRef", "Release"]
        ]

    def write(self, f, indent):
        f.write(f"{indent}unsafe record struct {self.basename}Ptr(IntPtr Pointer)\n")
        f.write(indent + "{\n")
        f.write(indent + f"    public {self.basename}? Deref() => {self.basename}.Create(this);\n")
        f.write(indent + "}\n")
        f.write("\n")
        f.write(f"{indent}unsafe class {self.basename}: CallableCOMWrapper\n")
        f.write(indent + "{\n")
        f.write(indent + f"    ref readonly {self.name}VTable VTable => ref Unsafe.AsRef<{self.name}VTable>(_vtable);\n")
        f.write(indent + f"    public static {self.basename}? Create(IntPtr punk) => punk != IntPtr.Zero ? new {self.basename}(punk) : null;\n")
        f.write(indent + f"    public static {self.basename}? Create({self.basename}Ptr p) => Create(p.Pointer);\n")
        f.write(indent + f"    {self.basename}(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.{self.name}, punk)\n")
        f.write(indent + "    {\n")
        f.write(indent + "        SuppressRelease();\n")
        f.write(indent + "    }\n")
        f.write("\n")
        for method in self.methods:
            method.write_impl(f, indent + "    ")

        f.write(indent + "    [StructLayout(LayoutKind.Sequential)]\n")
        f.write(indent + f"    private readonly struct {self.name}VTable\n")
        f.write(indent + "    {\n")
        for method in self.methods:
            method.write_ptr(f, indent + "        ")
        f.write(indent + "    }\n")
        f.write(indent + "}\n")
        f.write("\n")

class ComStruct():
    def __init__(self):
        self.name = ""
        self.fields = []
    
    def define(self, cursor, generator, name):
        self.name = cursor.displayname
        if self.name == "" or self.name is None:
            self.name = name
        self.fields = [generated for field in cursor.type.get_fields() for generated in ComStruct.generate_field(field, generator)]

    def write(self, f, indent):
        f.write(indent + "[StructLayout(LayoutKind.Explicit)]\n")
        f.write(f"{indent}unsafe struct {self.name}\n")
        f.write(indent + "{\n");
        for (name, offset, type) in self.fields:
            findent = indent + "    "
            f.write(f"{findent}[FieldOffset({offset})]\n")
            # Big hack, but why not
            bracket_idx = type.find("[")
            if bracket_idx >= 0:
                f.write(f"{findent}fixed {type[:bracket_idx]} {name}{type[bracket_idx:]};\n")
            else:
                f.write(f"{findent}public {type} {escape_name(name)};\n")
        f.write(indent + "}\n")
    
    def generate_field(field, generator, offset=None):
        canon = field.type.get_canonical()
        if offset is None:
            offset = field.get_field_offsetof()

        if canon.kind == clang.cindex.TypeKind.RECORD and canon.get_declaration().displayname == "":
            # Embedded record type
            return [generated for child in canon.get_fields() for generated in ComStruct.generate_field(child, generator, offset=offset + child.get_field_offsetof())]
        return [(field.displayname, offset, generator.resolve_type(field.type))]

class ComEnum():
    def __init__(self):
        self.name = ""
        self.values = []
    
    def define(self, cursor, generator, name):
        self.name = cursor.displayname
        if self.name == "" or self.name is None:
            self.name = name
        self.fields = [(field.displayname, field.enum_value) for field in cursor.get_children()]

    def write(self, f, indent):
        f.write(f"{indent}enum {self.name}\n")
        f.write(indent + "{\n");
        for (name, value) in self.fields:
            findent = indent + "    "
            f.write(f"{findent}{escape_name(name)} = {value},\n")
        f.write(indent + "}\n")

class ComGenerator():
    root_names = []
    types = {}
    idx = clang.cindex.Index.create()

    def add_root(self, name):
        self.root_names.append(name)

    def add_wrapper(self, name, interfaces):
        for iface in interfaces:
            self.root_names.append(iface)

    def walk(self, content):
        tu = self.idx.parse('cordebug.h', unsaved_files=[('cordebug.h', content)])

        while len(self.root_names) > 0:
            for cursor in tu.cursor.get_children():
                if cursor.kind == clang.cindex.CursorKind.STRUCT_DECL and cursor.displayname in self.root_names:
                    self.resolve_type(cursor.type)
                    self.root_names.remove(cursor.displayname)

    def generate_type(self, cursor):
        if cursor.kind == clang.cindex.CursorKind.STRUCT_DECL and cursor.displayname.endswith("Vtbl"):
            return ComInterface.generate(cursor, self)
        ipdb.set_trace()

    def resolve_type(self, typ, ptr_level=0):
        if typ.get_declaration().displayname in mapped_types:
            return mapped_types[typ.get_declaration().displayname]

        t = typ.get_canonical()
        if t.kind == clang.cindex.TypeKind.POINTER:
            pointee = t.get_pointee()
            inner = self.resolve_type(pointee, ptr_level=ptr_level + 1)
            if inner.endswith("Rec"):
                return inner.replace("Rec", "Ptr")
            return f"{inner}*"
        elif t.kind == clang.cindex.TypeKind.RECORD:
            name = t.get_declaration().displayname or t.spelling

            if name == "_GUID":
                return "Guid"

            if name == "IUnknown" or name == "IStream":
                return f"IntRec"

            if name.endswith("Vtbl") or not name.startswith("I"):
                return self.define_type(t).name

            if name.startswith("I"):
                basename = name[1:]
                if name not in self.types:
                    self.root_names.append(f"{name}Vtbl")
                return f"{basename}Rec"
            ipdb.set_trace()
            raise "Unsupported record"
        elif ptr_level > 0 and t.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
            return "void"
        elif t.kind == clang.cindex.TypeKind.INCOMPLETEARRAY:
            inner = self.resolve_type(t.element_type, ptr_level=ptr_level)
            return f"{inner}[]"
        elif t.kind == clang.cindex.TypeKind.CONSTANTARRAY:
            inner = self.resolve_type(t.element_type, ptr_level=ptr_level)
            return f"{inner}[{t.element_count}]"
        elif t.kind == clang.cindex.TypeKind.ENUM:
            return self.define_type(t).name
        elif t.kind == clang.cindex.TypeKind.LONGLONG:
            return "long"
        elif t.kind == clang.cindex.TypeKind.ULONGLONG:
            return "ulong"
        elif t.kind == clang.cindex.TypeKind.INT:
            return "int"
        elif t.kind == clang.cindex.TypeKind.UINT:
            return "uint"
        elif t.kind == clang.cindex.TypeKind.SHORT:
            return "short"
        elif t.kind == clang.cindex.TypeKind.USHORT:
            return "ushort"
        elif t.kind == clang.cindex.TypeKind.UCHAR:
            return "byte"
        elif t.kind == clang.cindex.TypeKind.CHAR_S:
            return "char"
        elif t.kind == clang.cindex.TypeKind.VOID:
            return "void"
        else:
            ipdb.set_trace()
            return "Unknown type"

    def define_type(self, typ):
        decl = typ.get_declaration()
        name = decl.displayname.replace("Vtbl", "") if decl.kind == clang.cindex.CursorKind.STRUCT_DECL and decl.displayname.endswith("Vtbl") else decl.displayname
        if name == "":
            name = typ.spelling

        if name in self.types:
            return self.types[name]
        else:
            if decl.kind == clang.cindex.CursorKind.STRUCT_DECL and name.startswith("I"):
                iface = ComInterface()
                self.types[name] = iface
                iface.define(decl, self, name)
                return iface
            elif decl.kind == clang.cindex.CursorKind.STRUCT_DECL:
                struct = ComStruct()
                self.types[name] = struct
                struct.define(decl, self, name)
                return struct
            elif decl.kind == clang.cindex.CursorKind.ENUM_DECL:
                enum = ComEnum()
                self.types[name] = enum
                enum.define(decl, self, name)
                return enum
            ipdb.set_trace()
            raise "Unknown declaration"

parser = optparse.OptionParser()
parser.add_option("--runtime-root", dest="runtime_root", default="", help="Path to the runtime root")
parser.add_option("--output-root", dest="output_root", default="", help="Path to generate C# files")

(options, args) = parser.parse_args()

if options.runtime_root == "":
    print("Please specify the root of the 'dotnet/runtime' repo with '--runtime-root'")
    exit(1)

if options.output_root == "":
    print("Please specify the output path with '--output-root'")
    exit(1)

runtime_root = os.path.abspath(options.runtime_root)
output_root = os.path.abspath(options.output_root)

print(f"Generating COM Wrappers...")

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

gen = ComGenerator()
gen.add_root("ICorDebugVtbl")
gen.add_wrapper("CorDebugManagedCallbackBase", ["ICorDebugManagedCallback", "ICorDebugManagedCallback2"])
gen.walk(processed)

# Now define some implementable wrappers
wrappers = [
    ComWrapper("CorDebugManagedCallbackBase", [
        gen.types["ICorDebugManagedCallback"],
        gen.types["ICorDebugManagedCallback2"]
    ])
]

# Create output directory if it doesn't exist
if not os.path.exists(output_root):
    os.makedirs(output_root)

output_file = os.path.join(output_root, "cordebug.cs")
with open(output_file, "w") as f:
    f.write("// ReSharper disable All\n")
    f.write("using System.Runtime.CompilerServices;\n")
    f.write("using System.Runtime.InteropServices;\n")
    f.write("\n")
    f.write("namespace OmniDebug.Interop;\n")
    f.write("\n")
    for t in gen.types.values():
        t.write(f, "")
        f.write("\n")

    for w in wrappers:
        w.write(f, "")
        f.write("\n")

print(f"Wrote COM wrappers to {output_file}")