import ipdb
import clang.cindex

class DotNetType():
    def get_canonical(self):
        return self
    
    def get_underlying(self):
        return self
    
    def get_param_form(self):
        ipdb.set_trace()
        raise "Not implemented"
    
    def get_field_form(self):
        return self.get_param_form()
    
    def get_field_name(self, field_name):
        return field_name
    
    def get_param_name(self, param_name):
        return param_name

class Primitive(DotNetType):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name
    
    def get_param_form(self):
        return self.name
    
    def get_field_form(self):
        return self.name

Primitive.mappings = {
    clang.cindex.TypeKind.LONGLONG: Primitive("long"),
    clang.cindex.TypeKind.ULONGLONG: Primitive("ulong"),
    clang.cindex.TypeKind.INT: Primitive("int"),
    clang.cindex.TypeKind.UINT: Primitive("uint"),
    clang.cindex.TypeKind.SHORT: Primitive("short"),
    clang.cindex.TypeKind.USHORT: Primitive("ushort"),
    clang.cindex.TypeKind.UCHAR: Primitive("char"),
    clang.cindex.TypeKind.CHAR_S: Primitive("char"),
    clang.cindex.TypeKind.CHAR_U: Primitive("char"),
}

class Function(DotNetType):
    def __init__(self, ret_type: DotNetType, args: list[DotNetType]):
        self.ret_type = ret_type
        self.args = args

    def __repr__(self):
        args = [ str(x) for x in self.args ]
        return f"Function<{', '.join(args)}, {self.ret_type}>"

    def get_param_form(self):
        ipdb.set_trace()
        raise Exception("Function must be accessed through a pointer")

class Void(DotNetType):
    def __repr__(self):
        return "void"

    def get_param_form(self):
        raise Exception("Void must be accessed through a pointer")

class Array(DotNetType):
    def __init__(self, element_type: DotNetType, size: int = None):
        self.element_type = element_type
        self.size = size

    def __repr__(self):
        return f"Array<{self.element_type}, {self.size}>"

    def get_underlying(self):
        return self.element_type.get_underlying()

    def get_param_form(self):
        return f"{self.element_type.get_param_form()}[]"

    def get_field_form(self):
        if self.size is None:
            return f"{self.element_type.get_field_form()}[]"
        else:
            return f"fixed {self.element_type.get_field_form()}"

    def get_field_name(self, field_name):
        if self.size is None:
            return f"{field_name}"
        else:
            return f"{field_name}[{self.size}]"

class DeclaredType(DotNetType):
    def __init__(self, declaration):
        self._name = None
        self.declaration = declaration

    def set_name(self, val):
        self._name = val

    @property
    def name(self):
        return self._name or self.declaration.displayname

class Enum(DeclaredType):
    def __init__(self, declaration):
        super().__init__(declaration)

    def __repr__(self):
        return f"enum {self.name}"

    def get_param_form(self):
        return self.name

class Struct(DeclaredType):
    def __init__(self, declaration):
        super().__init__(declaration)

    def __repr__(self):
        return f"struct {self.name}"

    def get_param_form(self):
        return self.name.lstrip('_')

class Interface(DeclaredType):
    def __init__(self, declaration):
        super().__init__(declaration)

    @property
    def name(self):
        return self.declaration.displayname.replace("Vtbl", "")

    @property
    def is_vtable(self):
        return self.declaration.displayname.endswith("Vtbl")

    def __repr__(self):
        return f"interface {self.name}"

    def get_param_form(self):
        ipdb.set_trace()
        raise Exception("Interface must be accessed through a pointer")

class TypeDef(DotNetType):
    def __init__(self, name: str, canonical: DotNetType):
        self.name = name
        self.canonical = canonical

    def get_canonical(self):
        canon = self.canonical
        if isinstance(canon, DeclaredType) and canon.name == "":
            canon.set_name(self.name)
        return canon

    def get_underlying(self):
        return self.get_canonical().get_underlying()

    def __repr__(self):
        return f"TypeDef<{self.name}, {self.canonical}>"

    def get_param_form(self):
        return self.canonical.get_param_form()

class Pointer(DotNetType):
    def __init__(self, pointee):
        self.pointee = pointee

    def __repr__(self):
        return f"Pointer<{self.pointee}>"

    def get_canonical(self):
        return Pointer(self.pointee.get_canonical())

    def get_underlying(self):
        return self.pointee.get_underlying()
    
    def get_param_name(self, param_name):
        if isinstance(self.pointee, Pointer) or isinstance(self.pointee, Interface) or isinstance(self.pointee, Void):
            return param_name
        else:
            return f"ref {param_name}"

    def get_field_form(self):
        t = self.get_canonical()
        # If the inner type is a pointer, we need to be a pointer
        if isinstance(t.pointee, Interface):
            # Special cases for IUnknown and IStrema
            if t.pointee.name == "IUnknown" or t.pointee.name == "IStream":
                return "IntPtr"
            # Use the special pointer type we create for each interface
            return f"{t.pointee.name[1:]}Ptr"
        elif isinstance(t.pointee, Void):
            return f"IntPtr"
        elif isinstance(t.pointee, Function):
            ret = t.pointee.ret_type.get_param_form()
            args = [ x.get_param_form() for x in t.pointee.args ]
            return f"delegate* unmanaged[Stdcall]<{', '.join(args)}, {ret}>"
        else:
            return f"{t.pointee.get_field_form()}*"

    def get_param_form(self):
        t = self.get_canonical()
        # If the inner type is a pointer, we need to be a pointer
        if isinstance(t.pointee, Pointer):
            return f"{t.pointee.get_param_form()}*"
        elif isinstance(t.pointee, Interface):
            # Special cases for IUnknown and IStrema
            if t.pointee.name == "IUnknown" or t.pointee.name == "IStream":
                return "IntPtr"
            # Use the special pointer type we create for each interface
            return f"{t.pointee.name[1:]}Ptr"
        elif isinstance(t.pointee, Void):
            return f"IntPtr"
        elif isinstance(t.pointee, Function):
            ret = t.pointee.ret_type.get_param_form()
            args = [ x.get_param_form() for x in t.pointee.args ]
            return f"delegate* unmanaged[Stdcall]<{', '.join(args)}, {ret}>"
        else:
            # But if not, we can use 'ref'
            return f"ref {t.pointee.get_param_form()}"

def map_dotnet_type(typ) -> DotNetType:
    mapped = Primitive.mappings.get(typ.kind)
    if mapped is not None:
        return mapped

    if typ.kind == clang.cindex.TypeKind.ELABORATED:
        return map_dotnet_type(typ.get_canonical())

    if typ.kind == clang.cindex.TypeKind.TYPEDEF:
        canon = map_dotnet_type(typ.get_canonical())
        return TypeDef(typ.spelling, canon)

    if typ.kind == clang.cindex.TypeKind.RECORD:
        decl = typ.get_declaration()
        if decl.displayname.startswith("I"):
            return Interface(decl)
        else:
            return Struct(decl)

    if typ.kind == clang.cindex.TypeKind.POINTER:
        pointee = map_dotnet_type(typ.get_pointee())
        return Pointer(pointee)

    if typ.kind == clang.cindex.TypeKind.INCOMPLETEARRAY:
        inner = map_dotnet_type(typ.element_type)
        return Array(inner)

    if typ.kind == clang.cindex.TypeKind.CONSTANTARRAY:
        inner = map_dotnet_type(typ.element_type)
        return Array(inner, typ.element_count)

    if typ.kind == clang.cindex.TypeKind.ENUM:
        return Enum(typ.get_declaration())

    if typ.kind == clang.cindex.TypeKind.VOID:
        return Void()

    if typ.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
        ret = map_dotnet_type(typ.get_result())
        args = [map_dotnet_type(arg) for arg in typ.argument_types()]
        return Function(ret, args)

    ipdb.set_trace()
    return "Unknown type"
