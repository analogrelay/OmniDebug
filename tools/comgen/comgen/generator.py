import ipdb
import clang.cindex

from comgen.types import Primitive, TypeDef, Struct, DeclaredType, Interface, Enum, map_dotnet_type

reserved_words = ['string']

def _write_file_header(f):
    f.write("// ReSharper disable All\n")
    f.write("using System.Runtime.CompilerServices;\n")
    f.write("using System.Runtime.InteropServices;\n")
    f.write("\n")
    f.write("namespace OmniDebug.Interop;\n")
    f.write("\n")

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
    
    def write(self, f):
        _write_file_header(f)
        f.write(f"unsafe abstract class {self.name}: COMCallableIUnknown\n")
        f.write("{\n")
        for iface in self.ifaces:
            f.write("    public " + iface.basename + "Ptr " + iface.name + " { get; }\n")
        f.write("\n")
        f.write(f"    public {self.name}()\n")
        f.write("    {\n")
        for iface in self.ifaces:
            f.write(f"        {iface.name} = Define{iface.name}(this, InterfaceIds.{iface.name});\n")
        f.write("    }\n")
        f.write("\n")
        for iface in self.ifaces:
            for method in iface.methods:
                f.write(f"    protected virtual {method.return_type.get_field_form()} {method.name}(")
                for i, (name, type) in enumerate(method.parameters):
                    if i > 0:
                        f.write(", ")
                    f.write(f"{type.get_param_form()} {name}")
                f.write(")\n")
                f.write("    {\n")
                f.write("        return HResult.E_NOTIMPL;\n")
                f.write("    }\n")
                f.write("\n")
        for iface in self.ifaces:
            f.write(f"    static {iface.basename}Ptr Define{iface.name}({self.name} self, Guid iid)\n")
            f.write("    {\n")
            f.write("        var builder = self.AddInterface(iid, validate: false);\n")
            for method in iface.methods:
                f.write(f"        builder.AddMethod(new {iface.name}Delegates.{method.name}Delegate((IntPtr Self")
                for (name, type) in method.parameters:
                    f.write(", " + type.get_param_form() + " " + name)
                f.write(f") => self.{method.name}(")
                for i, (name, type) in enumerate(method.parameters):
                    if i != 0:
                        f.write(", ")
                    f.write(type.get_param_name(name))
                f.write(")));\n")
            f.write(f"        return new {iface.basename}Ptr(builder.Complete());\n")
            f.write("    }\n")
            f.write("\n")

        for iface in self.ifaces:
            f.write(f"    static class {iface.name}Delegates\n")
            f.write("    {\n")
            for method in iface.methods:
                f.write("        [UnmanagedFunctionPointer(CallingConvention.Winapi)]\n")
                f.write(f"        public delegate {method.return_type} {method.name}Delegate(IntPtr self")
                for i, (name, type) in enumerate(method.parameters):
                    f.write(f", {type.get_param_form()} {name}")
                f.write(");\n")
                f.write("\n")
            f.write("    }\n")
            f.write("\n")
        f.write("}\n")

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
            f.write(f"{type.get_param_form()} {escape_name(name)}")
        f.write(")\n")
        f.write(indent + f"    => VTable.{self.name}Ptr(Self")
        for i, (name, type) in enumerate(self.parameters):
            f.write(", ")
            f.write(f"{type.get_param_name(escape_name(name))}")
        f.write(");\n")
        f.write("\n")

    def write_ptr(self, f, indent):
        f.write(indent + f"public readonly delegate* unmanaged[Stdcall]<IntPtr, ")
        for _, type in self.parameters:
            f.write(f"{type.get_param_form()}, ")
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

    def write(self, f):
        f.write(f"unsafe record struct {self.basename}Ptr(IntPtr Pointer)\n")
        f.write("{\n")
        f.write(f"    public {self.basename}? DerefOrDefault() => {self.basename}.Create(this);\n")
        f.write(f"    public {self.basename} Deref() => {self.basename}.Create(this) ?? throw new InvalidOperationException(\"Pointer was null\");\n")
        f.write("}\n")
        f.write("\n")
        f.write(f"unsafe class {self.basename}: CallableCOMWrapper\n")
        f.write("{\n")
        f.write(f"    ref readonly {self.name}VTable VTable => ref Unsafe.AsRef<{self.name}VTable>(_vtable);\n")
        f.write(f"    public static {self.basename}? Create(IntPtr punk) => punk != IntPtr.Zero ? new {self.basename}(punk) : null;\n")
        f.write(f"    public static {self.basename}? Create({self.basename}Ptr p) => Create(p.Pointer);\n")
        f.write(f"    {self.basename}(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.{self.name}, punk)\n")
        f.write("    {\n")
        f.write("        SuppressRelease();\n")
        f.write("    }\n")
        f.write("\n")
        for method in self.methods:
            method.write_impl(f, "    ")

        f.write("    [StructLayout(LayoutKind.Sequential)]\n")
        f.write(f"    private readonly struct {self.name}VTable\n")
        f.write("    {\n")
        for method in self.methods:
            method.write_ptr(f, "        ")
        f.write("    }\n")
        f.write("}\n")
        f.write("\n")

class ComStruct():
    def __init__(self):
        self.name = ""
        self.fields = []
    
    def define(self, cursor, generator, name):
        self.name = cursor.displayname
        if self.name == "" or self.name is None:
            self.name = name
        self.name = name.lstrip("_")
        self.fields = [generated for field in cursor.type.get_fields() for generated in ComStruct.generate_field(field, generator)]

    def write(self, f):
        f.write("[StructLayout(LayoutKind.Explicit)]\n")
        f.write(f"unsafe struct {self.name}\n")
        f.write("{\n");
        for (name, offset, type) in self.fields:
            f.write(f"    [FieldOffset({offset})]\n")
            f.write(f"    public {type.get_field_form()} {type.get_field_name(escape_name(name))};\n")
        f.write("}\n")
    
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

    def write(self, f):
        f.write(f"enum {self.name}\n")
        f.write("{\n");
        for (name, value) in self.fields:
            findent = "    "
            f.write(f"    {escape_name(name)} = {value},\n")
        f.write("}\n")

class ComGenerator():
    types = {
        # Pre-define the core COM types.
        "IUnknown": ComInterface(),
        "IStream": ComInterface(),
    }
    root_names = []
    files = {}
    mapped_types = {}
    file_types = None
    idx = clang.cindex.Index.create()

    def map_type(self, src, target):
        self.mapped_types[src] = target

    def walk(self, content, file, roots, clang_args = []):
        tu = self.idx.parse(file, args = clang_args, unsaved_files=[(file, content)])
        self.file_types = []
        self.root_names = roots

        while len(self.root_names) > 0:
            for cursor in tu.cursor.get_children():
                if cursor.kind == clang.cindex.CursorKind.STRUCT_DECL and cursor.is_definition() and cursor.displayname in self.root_names:
                    if cursor.is_abstract_record():
                        # C++-style
                        ipdb.set_trace()
                    else:
                        # C-style
                        self.resolve_type(cursor.type)
                    self.root_names.remove(cursor.displayname)
        
        self.files[file] = self.file_types

    def write_file(self, f, source_file):
        _write_file_header(f)
        for type_name in self.files.get(source_file, []):
            type = self.types.get(type_name)
            if type is not None:
                type.write(f) 
                f.write("\n")
    
    def write_wrapper(self, f, name, ifaces):
        resolved_ifaces = [ self.types[name] for name in ifaces ]
        ComWrapper(name, resolved_ifaces).write(f)

    def generate_type(self, cursor):
        if cursor.kind == clang.cindex.CursorKind.STRUCT_DECL and cursor.displayname.endswith("Vtbl"):
            return ComInterface.generate(cursor, self)
        ipdb.set_trace()

    def resolve_type(self, typ):
        if typ.spelling in self.mapped_types:
            return Primitive(self.mapped_types[typ.spelling])

        dotnet_type = map_dotnet_type(typ)
        underlying = dotnet_type.get_underlying()
        if isinstance(underlying, DeclaredType):
            self.declare_type(underlying, underlying.declaration)
        canon = dotnet_type.get_canonical()
        return canon

    def declare_type(self, type: DeclaredType, decl):
        if type.name == "":
            ipdb.set_trace()

        if type.name in self.types:
            return

        canon = type.get_canonical()
        if isinstance(canon, Interface):
            if not canon.is_vtable:
                # This isn't the Vtbl for the interface
                # So add that to the queue to be defined later
                self.root_names.append(canon.name + "Vtbl")
            else:
                iface = ComInterface()
                self.types[type.name] = iface
                self.file_types.append(type.name)
                iface.define(decl, self, type.name)
        elif isinstance(canon, Enum):
            enum = ComEnum()
            self.types[type.name] = enum
            self.file_types.append(type.name)
            enum.define(decl, self, type.name)
        elif isinstance(canon, Struct):
            struct = ComStruct()
            self.types[type.name] = struct
            self.file_types.append(type.name)
            struct.define(decl, self, type.name)
        else:
            ipdb.set_trace()
            raise "Unknown declaration"
